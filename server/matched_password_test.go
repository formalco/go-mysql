package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/test_util/test_keys"
	"github.com/stretchr/testify/require"
)

type matchedPasswordHandler struct {
	credential Credential
	index      int
	matched    bool
	success    bool
	fullAuth   bool
	reject     error
}

func (h *matchedPasswordHandler) GetCredential(string) (Credential, bool, error) {
	return h.credential, true, nil
}

func (h *matchedPasswordHandler) OnAuthSuccess(c *Conn) error {
	h.index, h.matched = c.MatchedPasswordIndex()
	h.success = true
	h.fullAuth = c.cachingSha2FullAuth
	return h.reject
}

func (h *matchedPasswordHandler) OnAuthFailure(c *Conn, _ error) {
	h.index, h.matched = c.MatchedPasswordIndex()
	h.fullAuth = c.cachingSha2FullAuth
}

// Run a real client/server handshake without requiring an external database.
// Each connection uses a fresh handler, while callers may share a Server to
// exercise its authentication cache across connections.
func runMatchedPasswordHandshake(t *testing.T, s *Server, h *matchedPasswordHandler, password string, useTLS bool) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, serverConn.SetDeadline(deadline))
	require.NoError(t, clientConn.SetDeadline(deadline))
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		_, err := s.NewCustomizedConn(serverConn, h, &EmptyHandler{})
		done <- err
	}()

	var options []client.Option
	if useTLS {
		options = append(options, func(c *client.Conn) error {
			c.SetTLSConfig(&tls.Config{InsecureSkipVerify: true}) // Test certificate only.
			return nil
		})
	}
	c, clientErr := client.ConnectWithDialer(context.Background(), "tcp", "pipe", "user", password, "",
		func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }, options...)
	if c != nil {
		// Close the pipe directly to avoid waiting for TLS close notifications.
		clientConn.Close()
	}
	serverErr := <-done
	if clientErr == nil {
		require.NoError(t, serverErr)
	} else {
		require.Error(t, serverErr)
	}
	return clientErr
}

func TestMatchedPasswordIndexHandshake(t *testing.T) {
	methods := []string{mysql.AUTH_NATIVE_PASSWORD, mysql.AUTH_SHA256_PASSWORD, mysql.AUTH_CACHING_SHA2_PASSWORD}
	cases := []struct {
		name      string
		passwords []string
		password  string
		index     int
		matched   bool
	}{
		{"first", []string{"selected", "other"}, "selected", 0, true},
		{"later", []string{"other", "selected"}, "selected", 1, true},
		{"duplicate", []string{"other", "selected", "selected"}, "selected", 1, true},
		{"empty", []string{"other", "", ""}, "", 1, true},
		{"wrong", []string{"other", "selected"}, "wrong", 0, false},
		{"empty_rejected", []string{"other", "selected"}, "", 0, false},
	}
	for _, method := range methods {
		for _, useTLS := range []bool{false, true} {
			for _, switchPlugin := range []bool{false, true} {
				for _, tc := range cases {
					t.Run(fmt.Sprintf("%s/tls=%t/switch=%t/%s", method, useTLS, switchPlugin, tc.name), func(t *testing.T) {
						initialMethod := method
						if switchPlugin {
							initialMethod = mysql.AUTH_NATIVE_PASSWORD
							if method == initialMethod {
								initialMethod = mysql.AUTH_CACHING_SHA2_PASSWORD
							}
						}
						s := NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, initialMethod, test_keys.RSAKey(), tlsConf)
						h := &matchedPasswordHandler{credential: Credential{Passwords: tc.passwords, AuthPluginName: method}}
						err := runMatchedPasswordHandshake(t, s, h, tc.password, useTLS)
						if tc.matched {
							require.NoError(t, err)
						} else {
							require.ErrorContains(t, err, "Access denied")
						}
						require.Equal(t, tc.matched, h.success)
						require.Equal(t, tc.matched, h.matched)
						require.Equal(t, tc.index, h.index)
					})
				}
			}
		}
	}
}

func TestMatchedPasswordIndexCachingSHA2(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", useTLS), func(t *testing.T) {
			s := NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_CACHING_SHA2_PASSWORD, test_keys.RSAKey(), tlsConf)
			cases := []struct {
				name      string
				passwords []string
				password  string
				index     int
				matched   bool
				fullAuth  bool
			}{
				{"populate_cache", []string{"other", "selected"}, "selected", 1, true, true},
				{"cache_hit", []string{"other", "selected"}, "selected", 1, true, false},
				{"reordered", []string{"selected", "other"}, "selected", 0, true, false},
				{"duplicates", []string{"other", "selected", "selected"}, "selected", 1, true, false},
				{"removed", []string{"replacement", "other"}, "selected", 0, false, true},
				{"different_password", []string{"replacement", "other"}, "other", 1, true, true},
				{"new_cache_hit", []string{"replacement", "other"}, "other", 1, true, false},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					h := &matchedPasswordHandler{credential: Credential{Passwords: tc.passwords, AuthPluginName: mysql.AUTH_CACHING_SHA2_PASSWORD}}
					err := runMatchedPasswordHandshake(t, s, h, tc.password, useTLS)
					if tc.matched {
						require.NoError(t, err)
					} else {
						require.ErrorContains(t, err, "Access denied")
					}
					require.Equal(t, tc.matched, h.success)
					require.Equal(t, tc.matched, h.matched)
					require.Equal(t, tc.index, h.index)
					require.Equal(t, tc.fullAuth, h.fullAuth)
				})
			}
		})
	}
}

func TestMatchedPasswordIndexPolicyRejection(t *testing.T) {
	s := NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, nil, nil)
	h := &matchedPasswordHandler{
		credential: Credential{Passwords: []string{"other", "selected"}, AuthPluginName: mysql.AUTH_NATIVE_PASSWORD},
		reject:     errors.New("rejected by session policy"),
	}
	err := runMatchedPasswordHandshake(t, s, h, "selected", false)
	require.ErrorContains(t, err, h.reject.Error())
	require.True(t, h.success)
	require.True(t, h.matched)
	require.Equal(t, 1, h.index)
}

func TestMatchedPasswordIndexUnavailable(t *testing.T) {
	c := &Conn{}
	index, matched := c.MatchedPasswordIndex()
	require.Zero(t, index)
	require.False(t, matched)

	c.credential = Credential{Passwords: []string{"selected"}, AuthPluginName: mysql.AUTH_NATIVE_PASSWORD}
	c.salt = []byte("01234567890123456789")
	c.serverConf = &Server{authProvider: &DefaultAuthenticationProvider{}}
	require.NoError(t, c.compareAuthData(mysql.AUTH_NATIVE_PASSWORD, mysql.CalcNativePassword(c.salt, []byte("selected"))))
	require.ErrorIs(t, c.compareAuthData(mysql.AUTH_NATIVE_PASSWORD, mysql.CalcNativePassword(c.salt, []byte("wrong"))), ErrAccessDenied)
	_, matched = c.MatchedPasswordIndex()
	require.False(t, matched)
}

type matchedPasswordProvider struct {
	DefaultAuthenticationProvider
	authenticate func(*Conn, string, []byte) error
}

func (p *matchedPasswordProvider) Authenticate(c *Conn, method string, data []byte) error {
	return p.authenticate(c, method, data)
}

func TestMatchedPasswordIndexCustomProvider(t *testing.T) {
	for _, delegate := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			t.Run(fmt.Sprintf("delegate=%t/reject=%t", delegate, reject), func(t *testing.T) {
				provider := &matchedPasswordProvider{}
				provider.authenticate = func(c *Conn, method string, data []byte) error {
					if delegate {
						if err := provider.DefaultAuthenticationProvider.Authenticate(c, method, data); err != nil {
							return err
						}
					}
					if reject {
						return ErrAccessDenied
					}
					return nil
				}
				c := &Conn{
					credential: Credential{Passwords: []string{"other", "selected"}, AuthPluginName: mysql.AUTH_NATIVE_PASSWORD},
					salt:       []byte("01234567890123456789"),
					serverConf: &Server{authProvider: provider},
				}
				err := c.compareAuthData(mysql.AUTH_NATIVE_PASSWORD, mysql.CalcNativePassword(c.salt, []byte("selected")))
				if reject {
					require.ErrorIs(t, err, ErrAccessDenied)
				} else {
					require.NoError(t, err)
				}
				index, matched := c.MatchedPasswordIndex()
				require.Equal(t, delegate && !reject, matched)
				if matched {
					require.Equal(t, 1, index)
				}
			})
		}
	}
}
