package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/test_util/test_keys"
	"github.com/samber/mo"
	"github.com/stretchr/testify/require"
)

type tokenHandler struct {
	passwords []string
	calls     atomic.Int32
	matched   atomic.Pointer[mo.Option[string]]
}

func (h *tokenHandler) AuthenticatePassword(_ *Conn, password string) (bool, error) {
	h.calls.Add(1)
	switch password {
	case "token":
		return true, nil
	case "rejected":
		return false, ErrAccessDenied
	}
	return false, nil
}

func (h *tokenHandler) GetCredential(string) (Credential, bool, error) {
	return Credential{Passwords: h.passwords, AuthPluginName: mysql.AUTH_CACHING_SHA2_PASSWORD}, true, nil
}

func (h *tokenHandler) OnAuthSuccess(c *Conn) error {
	matched := c.MatchedPassword()
	h.matched.Store(&matched)
	return nil
}

func (*tokenHandler) OnAuthFailure(*Conn, error) {}

func serveTokenHandler(t *testing.T, h *tokenHandler) func(password string, useTLS bool) error {
	cert, err := tls.X509KeyPair(test_keys.CertPem, test_keys.KeyPem)
	require.NoError(t, err)
	s := NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_CACHING_SHA2_PASSWORD, test_keys.RSAKey(),
		&tls.Config{Certificates: []tls.Certificate{cert}})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = s.NewCustomizedConn(conn, h, &EmptyHandler{})
			}()
		}
	}()

	return func(password string, useTLS bool) error {
		h.matched.Store(nil)
		c, err := client.Connect(l.Addr().String(), "user", password, "", func(c *client.Conn) error {
			if useTLS {
				c.SetTLSConfig(&tls.Config{InsecureSkipVerify: true}) // Test certificate only.
			}
			return nil
		})
		if err == nil {
			c.Close()
		}
		return err
	}
}

func TestPasswordAuthenticator(t *testing.T) {
	h := &tokenHandler{passwords: []string{"secret", "rejected"}}
	connect := serveTokenHandler(t, h)

	for _, useTLS := range []bool{true, false} {
		require.NoError(t, connect("token", useTLS))
		require.Equal(t, mo.None[string](), *h.matched.Load())

		require.NoError(t, connect("secret", useTLS))
		require.Equal(t, mo.Some("secret"), *h.matched.Load())

		require.ErrorContains(t, connect("rejected", useTLS), "Access denied")
		require.ErrorContains(t, connect("wrong", useTLS), "Access denied")
	}

	// Tokens must be revalidated on every connection.
	calls := h.calls.Load()
	require.NoError(t, connect("token", true))
	require.NoError(t, connect("token", true))
	require.Equal(t, calls+2, h.calls.Load())
}

func TestPasswordAuthenticatorNoPasswords(t *testing.T) {
	h := &tokenHandler{}
	connect := serveTokenHandler(t, h)

	require.NoError(t, connect("token", true))
	require.ErrorContains(t, connect("wrong", true), "Access denied")
	require.ErrorContains(t, connect("", true), "Access denied")
	require.ErrorContains(t, connect("", false), "Access denied")
}

func TestPasswordAuthenticatorNoPasswordsFullAuthEmptyPassword(t *testing.T) {
	for _, password := range [][]byte{{}, {0x00}} {
		h := &tokenHandler{}
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() {
			serverConn.Close()
			clientConn.Close()
		})
		c := &Conn{
			Conn:        packet.NewConn(serverConn),
			serverConf:  NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_CACHING_SHA2_PASSWORD, test_keys.RSAKey(), nil),
			authHandler: h,
			salt:        []byte("01234567890123456789"),
		}
		encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &test_keys.RSAKey().PublicKey, mysql.Xor(password, c.salt), nil)
		require.NoError(t, err)

		require.ErrorIs(t, c.handleCachingSha2PasswordFullAuth(encrypted), ErrAccessDeniedNoPassword)
		require.Zero(t, h.calls.Load())
	}
}
