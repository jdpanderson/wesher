// Package control is the local operator interface to a running agent: a unix
// socket carrying one JSON request and one JSON response per connection.
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// DefaultSocket is where the agent for iface listens.
func DefaultSocket(iface string) string { return filepath.Join("/run/cheesecloth", iface+".sock") }

// Operations a Request may ask for.
const (
	OpInvite = "invite"
	OpRevoke = "revoke"
)

// Request is an operator command.
type Request struct {
	Op     string `json:"op"`               // OpInvite or OpRevoke
	TTL    string `json:"ttl,omitempty"`    // invite: token lifetime, a Go duration
	Uses   int    `json:"uses,omitempty"`   // invite: how many nodes may enrol with it
	Target string `json:"target,omitempty"` // revoke: node name or identity
}

// Response carries the result or an error message.
type Response struct {
	Token    string `json:"token,omitempty"`
	Identity string `json:"identity,omitempty"` // revoke: the identity that was revoked
	Error    string `json:"error,omitempty"`
}

// Handler performs the operations on behalf of the agent.
type Handler interface {
	Invite(ttl time.Duration, uses int) (string, error)
	// Revoke resolves target to an identity, revokes it and returns the identity.
	Revoke(target string) (string, error)
}

// Server answers requests on a unix socket.
type Server struct {
	handler Handler
	ln      net.Listener
	path    string
}

// maxSocketPath is the longest path a unix socket address can hold on this
// platform: 107 bytes on Linux, 103 on macOS and the BSDs.
var maxSocketPath = len(syscall.RawSockaddrUnix{}.Path) - 1

// Listen creates the socket at path (owner-only) and starts serving. The
// socket is created in a private directory and renamed into place once its
// mode is set, so it is never reachable by anyone else, not even briefly.
func Listen(path string, h Handler) (*Server, error) {
	dir := filepath.Dir(path)
	// the staging path is the final one plus a directory of this length
	if n := len(path) + len("/.control-0000000000"); n > maxSocketPath {
		return nil, fmt.Errorf("control socket path %s is too long: %d bytes with its staging directory, at most %d", path, n, maxSocketPath)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating control socket directory: %w", err)
	}
	// a stale socket from an unclean exit is replaced; anything else at the path is not ours to remove
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("control socket path %s exists and is not a socket", path)
	}
	staging, err := os.MkdirTemp(dir, ".control-*") // 0700
	if err != nil {
		return nil, fmt.Errorf("creating control socket: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	tmp := filepath.Join(staging, filepath.Base(path))
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("listening on control socket %s: %w", path, err)
	}
	if err = os.Chmod(tmp, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("securing control socket: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("placing control socket at %s: %w", path, err)
	}
	s := &Server{handler: h, ln: ln, path: path}
	go s.serve()
	return s, nil
}

// Close stops serving and removes the socket.
func (s *Server) Close() {
	_ = s.ln.Close()
	_ = os.Remove(s.path)
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			var req Request
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = json.NewEncoder(conn).Encode(Response{Error: "malformed request"})
				return
			}
			_ = json.NewEncoder(conn).Encode(s.handle(req))
		}()
	}
}

func (s *Server) handle(req Request) Response {
	switch req.Op {
	case OpInvite:
		ttl, err := time.ParseDuration(req.TTL)
		if err != nil {
			return Response{Error: "invalid ttl: " + err.Error()}
		}
		token, err := s.handler.Invite(ttl, req.Uses)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Token: token}
	case OpRevoke:
		id, err := s.handler.Revoke(req.Target)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Identity: id}
	default:
		return Response{Error: "unknown operation " + req.Op}
	}
}

// Call sends one request to the agent listening at path.
func Call(path string, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("connecting to the agent at %s (is it running, and are you root?): %w", path, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("reading the agent's reply: %w", err)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
