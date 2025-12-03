package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/errors"
)

var (
	ErrAccessDenied           = errors.New("access denied")
	ErrAccessDeniedNoPassword = fmt.Errorf("%w without password", ErrAccessDenied)
)

func (c *Conn) compareAuthData(authPluginName string, clientAuthData []byte) error {
	// If we have credentials for the client's auth method, use it
	if _, ok := c.credentials[authPluginName]; ok {
		return c.serverConf.authProvider.Authenticate(c, authPluginName, clientAuthData)
	}

	// Otherwise, switch to an auth method we have credentials for
	for method := range c.credentials {
		err := c.writeAuthSwitchRequest(method)
		if err != nil {
			return err
		}
		return c.handleAuthSwitchResponse()
	}

	return ErrAccessDenied
}

func (c *Conn) acquireCredentials() error {
	if len(c.credentials) > 0 {
		return nil
	}
	credentials, found, err := c.credentialProvider.GetCredentials(c.user)
	if err != nil {
		return err
	}
	if !found || len(credentials) == 0 {
		return mysql.NewDefaultError(mysql.ER_NO_SUCH_USER, c.user, c.RemoteAddr().String())
	}
	// Group credentials by auth plugin name
	c.credentials = make(map[string][]Credential)
	for _, cred := range credentials {
		c.credentials[cred.AuthPluginName] = append(c.credentials[cred.AuthPluginName], cred)
	}
	return nil
}

func errAccessDenied(credentials []Credential) error {
	// Check if all credentials have empty passwords
	allEmpty := true
	for _, c := range credentials {
		if c.Password != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return ErrAccessDeniedNoPassword
	}
	return ErrAccessDenied
}

func scrambleValidation(cached, nonce, scramble []byte) bool {
	// SHA256(SHA256(SHA256(STORED_PASSWORD)), NONCE)
	crypt := sha256.New()
	crypt.Write(cached)
	crypt.Write(nonce)
	message2 := crypt.Sum(nil)
	// SHA256(PASSWORD)
	if len(message2) != len(scramble) {
		return false
	}
	for i := range message2 {
		message2[i] ^= scramble[i]
	}
	// SHA256(SHA256(PASSWORD)
	crypt.Reset()
	crypt.Write(message2)
	m := crypt.Sum(nil)
	return subtle.ConstantTimeCompare(m, cached) == 1
}

func (c *Conn) compareNativePasswordAuthData(clientAuthData []byte) error {
	for _, credential := range c.credentials[mysql.AUTH_NATIVE_PASSWORD] {
		password, err := mysql.DecodePasswordHex(credential.Password)
		if err != nil {
			continue
		}
		if mysql.CompareNativePassword(clientAuthData, password, c.salt) {
			return nil
		}
	}
	return errAccessDenied(c.credentials[mysql.AUTH_NATIVE_PASSWORD])
}

func (c *Conn) compareSha256PasswordAuthData(clientAuthData []byte) error {
	credentials := c.credentials[mysql.AUTH_SHA256_PASSWORD]
	// Empty passwords are not hashed, but sent as empty string
	if len(clientAuthData) == 0 {
		for _, credential := range credentials {
			if credential.Password == "" {
				return nil
			}
		}
		return ErrAccessDenied
	}
	if tlsConn, ok := c.Conn.Conn.(*tls.Conn); ok {
		if !tlsConn.ConnectionState().HandshakeComplete {
			return errors.New("incomplete TSL handshake")
		}
		// connection is SSL/TLS, client should send plain password
		// deal with the trailing \NUL added for plain text password received
		if l := len(clientAuthData); l != 0 && clientAuthData[l-1] == 0x00 {
			clientAuthData = clientAuthData[:l-1]
		}
	} else {
		// client should send encrypted password
		// decrypt
		dbytes, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, (c.serverConf.tlsConfig.Certificates[0].PrivateKey).(*rsa.PrivateKey), clientAuthData, nil)
		if err != nil {
			return err
		}
		clientAuthData = mysql.Xor(dbytes, c.salt)
		if l := len(clientAuthData); l != 0 && clientAuthData[l-1] == 0x00 {
			clientAuthData = clientAuthData[:l-1]
		}
	}
	for _, credential := range credentials {
		check, err := mysql.Check256HashingPassword([]byte(credential.Password), string(clientAuthData))
		if err != nil {
			continue
		}
		if check {
			return nil
		}
	}
	return ErrAccessDenied
}

func (c *Conn) compareCacheSha2PasswordAuthData(clientAuthData []byte) error {
	credentials := c.credentials[mysql.AUTH_CACHING_SHA2_PASSWORD]
	// Empty passwords are not hashed, but sent as empty string
	if len(clientAuthData) == 0 {
		for _, credential := range credentials {
			if credential.Password == "" {
				return nil
			}
		}
		return ErrAccessDenied
	}
	// the caching of 'caching_sha2_password' in MySQL, see: https://dev.mysql.com/worklog/task/?id=9591
	// check if we have a cached value
	cacheKey := fmt.Sprintf("%s@%s", c.user, c.LocalAddr())
	cached, ok := c.serverConf.cacheShaPassword.Load(cacheKey)
	if ok {
		// Scramble validation
		if scrambleValidation(cached.([]byte), c.salt, clientAuthData) {
			// 'fast' auth: write "More data" packet (first byte == 0x01) with the second byte = 0x03
			return c.writeAuthMoreDataFastAuth()
		}

		// Cache mismatch with single credential means wrong password
		if len(credentials) == 1 {
			return errAccessDenied(credentials)
		}
		// Multiple credentials: fall through to full auth to try other credentials
	}
	// cache miss (or cache mismatch with multiple credentials), do full auth
	if err := c.writeAuthMoreDataFullAuth(); err != nil {
		return err
	}
	c.cachingSha2FullAuth = true
	return nil
}
