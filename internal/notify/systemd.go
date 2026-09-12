//go:build unix

package notify

import (
	"net"
	"os"
	"strings"
)

// Systemd speaks sd_notify(3) over the socket in $NOTIFY_SOCKET. Outside
// systemd, or under a unit that is not Type=notify, the variable is unset
// and every call is a no-op.
type Systemd struct{}

// Send delivers one notification made of the given assignments, e.g.
// "READY=1", "STATUS=3 peers". A missing NOTIFY_SOCKET is not an error.
func (Systemd) Send(assignments ...string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	// Go turns a leading '@' into the abstract-namespace form systemd uses.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(strings.Join(assignments, "\n")))
	return err
}

func (s Systemd) Ready(status string) error  { return s.Send("READY=1", "STATUS="+status) }
func (s Systemd) Status(status string) error { return s.Send("STATUS=" + status) }
func (s Systemd) Stopping() error            { return s.Send("STOPPING=1") }
