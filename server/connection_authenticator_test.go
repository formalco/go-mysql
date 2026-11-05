package server

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/test_util/test_keys"
	"github.com/stretchr/testify/require"
)

// clientCertificateHandler accepts any client that presents a TLS client certificate, and
// otherwise requires the password "secret".
type clientCertificateHandler struct{}

func (clientCertificateHandler) AuthenticateConnection(c *Conn) (bool, error) {
	tlsConn, ok := c.Conn.Conn.(*tls.Conn)
	return ok && len(tlsConn.ConnectionState().PeerCertificates) > 0, nil
}

func (clientCertificateHandler) GetCredential(string) (Credential, bool, error) {
	return Credential{Passwords: []string{"secret"}, AuthPluginName: mysql.AUTH_CACHING_SHA2_PASSWORD}, true, nil
}

func (clientCertificateHandler) OnAuthSuccess(*Conn) error { return nil }

func (clientCertificateHandler) OnAuthFailure(*Conn, error) {}

func TestConnectionAuthenticatorClientCertificate(t *testing.T) {
	cert, err := tls.X509KeyPair(test_keys.CertPem, test_keys.KeyPem)
	require.NoError(t, err)
	s := NewServer("8.0.12", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_CACHING_SHA2_PASSWORD, test_keys.RSAKey(),
		&tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert})
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
				_, _ = s.NewCustomizedConn(conn, clientCertificateHandler{}, &EmptyHandler{})
			}()
		}
	}()

	connect := func(password string, certificates ...tls.Certificate) error {
		c, err := client.Connect(l.Addr().String(), "user", password, "", func(c *client.Conn) error {
			c.SetTLSConfig(&tls.Config{InsecureSkipVerify: true, Certificates: certificates}) // Test certificate only.
			return nil
		})
		if err == nil {
			c.Close()
		}
		return err
	}

	require.NoError(t, connect("wrong", cert))
	require.ErrorContains(t, connect("wrong"), "Access denied")
	require.NoError(t, connect("secret"))
}
