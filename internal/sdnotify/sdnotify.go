// Package sdnotify tells systemd how the service is doing over the socket in
// $NOTIFY_SOCKET (see sd_notify(3)). Outside systemd, or under a unit that is
// not Type=notify, the variable is unset and every call is a no-op.
package sdnotify

import (
	"net"
	"os"
	"strings"
)

// Send delivers one notification made of the given assignments, e.g.
// "READY=1", "STATUS=3 peers". Errors are returned for the caller to log; a
// missing NOTIFY_SOCKET is not an error.
func Send(assignments ...string) error {
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

// Ready reports that the service is up, with a status line.
func Ready(status string) error { return Send("READY=1", "STATUS="+status) }

// Status replaces the status line systemctl shows.
func Status(status string) error { return Send("STATUS=" + status) }

// Stopping reports that the service has begun shutting down.
func Stopping() error { return Send("STOPPING=1") }
