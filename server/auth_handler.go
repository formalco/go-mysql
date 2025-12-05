package server

import (
	"sync"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/errors"
	"github.com/pingcap/tidb/pkg/parser/auth"
)

// AuthHandler provides user credentials and authentication lifecycle hooks.
//
// # Important Note
//
// if the password in a third-party auth handler could be updated at runtime, we have to invalidate the caching
// for 'caching_sha2_password' by calling 'func (s *Server)InvalidateCache(string, string)'.
type AuthHandler interface {
	// get user credentials (supports multiple valid credentials per user)
	GetCredentials(username string) (credentials []Credential, found bool, err error)

	// OnAuthSuccess is called after successful authentication, before the OK packet.
	// Return an error to reject the connection (error will be sent to client instead of OK).
	// Return nil to proceed with sending the OK packet.
	OnAuthSuccess(conn *Conn) error

	// OnAuthFailure is called after authentication fails, before the error packet.
	// This is informational only - the connection will be closed regardless.
	OnAuthFailure(conn *Conn, err error)
}

func NewInMemoryAuthHandler(defaultAuthMethod ...string) *InMemoryAuthHandler {
	d := mysql.AUTH_CACHING_SHA2_PASSWORD
	if len(defaultAuthMethod) > 0 {
		d = defaultAuthMethod[0]
	}
	return &InMemoryAuthHandler{
		userPool:          sync.Map{},
		defaultAuthMethod: d,
	}
}

type Credential struct {
	Password       string
	AuthPluginName string
}

// Hash computes the password hash for the credential's auth plugin.
func (c Credential) Hash() (string, error) {
	if c.Password == "" {
		return "", nil
	}

	switch c.AuthPluginName {
	case mysql.AUTH_NATIVE_PASSWORD:
		return mysql.EncodePasswordHex(mysql.NativePasswordHash([]byte(c.Password))), nil

	case mysql.AUTH_CACHING_SHA2_PASSWORD:
		return auth.NewHashPassword(c.Password, mysql.AUTH_CACHING_SHA2_PASSWORD), nil

	case mysql.AUTH_SHA256_PASSWORD:
		return mysql.NewSha256PasswordHash(c.Password)

	case mysql.AUTH_CLEAR_PASSWORD:
		return c.Password, nil

	default:
		return "", errors.Errorf("unknown authentication plugin name '%s'", c.AuthPluginName)
	}
}

func NewCredential(password string, authPluginName string) (Credential, error) {
	if !isAuthMethodSupported(authPluginName) {
		return Credential{}, errors.Errorf("unknown authentication plugin name '%s'", authPluginName)
	}
	return Credential{
		Password:       password,
		AuthPluginName: authPluginName,
	}, nil
}

// InMemoryAuthHandler implements AuthHandler with in-memory credential storage.
type InMemoryAuthHandler struct {
	userPool          sync.Map // username -> []Credential
	defaultAuthMethod string
}

func (h *InMemoryAuthHandler) CheckUsername(username string) (found bool, err error) {
	_, ok := h.userPool.Load(username)
	return ok, nil
}

func (h *InMemoryAuthHandler) GetCredentials(username string) (credentials []Credential, found bool, err error) {
	v, ok := h.userPool.Load(username)
	if !ok {
		return nil, false, nil
	}
	c, valid := v.([]Credential)
	if !valid {
		return nil, true, errors.Errorf("invalid credentials")
	}
	return c, true, nil
}

func (h *InMemoryAuthHandler) AddUser(username, password string, optionalAuthPluginName ...string) error {
	authPluginName := h.defaultAuthMethod
	if len(optionalAuthPluginName) > 0 {
		authPluginName = optionalAuthPluginName[0]
	}

	c, err := NewCredential(password, authPluginName)
	if err != nil {
		return err
	}

	h.userPool.Store(username, []Credential{c})
	return nil
}

func (h *InMemoryAuthHandler) OnAuthSuccess(conn *Conn) error {
	return nil
}

func (h *InMemoryAuthHandler) OnAuthFailure(conn *Conn, err error) {
}
