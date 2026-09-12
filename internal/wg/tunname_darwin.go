//go:build darwin

package wg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// macOS names tun interfaces itself (utunN), so the agent's name lives on the
// control socket only. The utun name is recorded next to the socket, in
// /var/run/wireguard/<name>.name, the file wg-quick(8) uses for the same
// purpose, so `status` and the tools can find the interface.

// nameDir is where the records live; tests point it at a temporary directory.
var nameDir = "/var/run/wireguard"

func tunName(string) string { return "utun" }

func nameFile(name string) string { return filepath.Join(nameDir, name+".name") }

// published records that the agent's name maps to the utun interface osName.
func published(name, osName string) error {
	if err := os.MkdirAll(nameDir, 0o755); err != nil {
		return fmt.Errorf("recording the interface name: %w", err)
	}
	if err := os.WriteFile(nameFile(name), []byte(osName+"\n"), 0o644); err != nil {
		return fmt.Errorf("recording the interface name: %w", err)
	}
	return nil
}

func unpublished(name string) error {
	if err := os.Remove(nameFile(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// osNameOf is the utun interface behind the agent's name, from the record
// published when it was created.
func osNameOf(name string) (string, error) {
	b, err := os.ReadFile(nameFile(name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
