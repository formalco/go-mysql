package server_test

import (
	"fmt"
	"log"
	"net"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
)

// labeledAuthenticationHandler is created once per connection. The credential
// and labels are an immutable snapshot, with one label per password.
type labeledAuthenticationHandler struct {
	username   string
	credential server.Credential
	labels     map[string]string
}

func (h *labeledAuthenticationHandler) GetCredential(username string) (server.Credential, bool, error) {
	return h.credential, username == h.username, nil
}

func (h *labeledAuthenticationHandler) OnAuthSuccess(c *server.Conn) error {
	password, ok := c.MatchedPassword().Get()
	if !ok {
		return fmt.Errorf("matched credential metadata unavailable")
	}
	label, found := h.labels[password]
	if !found {
		return fmt.Errorf("matched credential metadata unavailable")
	}
	log.Printf("authenticated credential: %s", label)
	return nil
}

func (h *labeledAuthenticationHandler) OnAuthFailure(*server.Conn, error) {}

func ExampleConn_MatchedPassword() {
	listener, err := net.Listen("tcp", "127.0.0.1:3306")
	if err != nil {
		log.Print(err)
		return
	}
	defer listener.Close()

	// Accept one connection for this example. A server would normally accept in
	// a loop and create a separate handler and snapshot for each connection.
	rawConn, err := listener.Accept()
	if err != nil {
		log.Print(err)
		return
	}
	defer rawConn.Close()

	handler := &labeledAuthenticationHandler{
		username: "user",
		credential: server.Credential{
			Passwords:      []string{"previous-secret", "current-secret"},
			AuthPluginName: mysql.AUTH_CACHING_SHA2_PASSWORD,
		},
		labels: map[string]string{"previous-secret": "previous", "current-secret": "current"},
	}
	conn, err := server.NewDefaultServer().NewCustomizedConn(rawConn, handler, &server.EmptyHandler{})
	if err != nil {
		log.Print(err)
		return
	}
	defer conn.Close()
	// A client using "current-secret" logs "authenticated credential: current".
}
