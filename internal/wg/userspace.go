package wg

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	wgdev "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// userspaceDevice runs WireGuard in this process, on a tun interface, and
// serves the standard userspace control socket under the agent's name, so
// wgctrl configures it exactly as it would a kernel device. It is the way
// on macOS and Windows, and the fallback on a Linux kernel without the
// module.
type userspaceDevice struct {
	// createTUN and listen make the tun interface and the control socket;
	// nil means the operating system's. Tests plug in a tun in memory and a
	// socket in a temporary directory.
	createTUN func(name string, mtu int) (tun.Device, error)
	listen    func(name string) (net.Listener, error)

	mu     sync.Mutex
	dev    *wgdev.Device
	uapi   net.Listener
	osName string
}

func (u *userspaceDevice) Kind() string { return "userspace" }

// Create starts the device unless it is already running. A device that
// stopped on its own is replaced.
func (u *userspaceDevice) Create(name string, mtu int) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dev != nil {
		select {
		case <-u.dev.Wait():
			slog.Warn("wireguard device stopped; starting it again", "iface", name)
			u.stop()
		default:
			return u.osName, nil
		}
	}

	createTUN, listen := u.createTUN, u.listen
	if createTUN == nil {
		createTUN = tun.CreateTUN
	}
	if listen == nil {
		listen = uapiListen
	}
	tdev, err := createTUN(tunName(name), mtu)
	if err != nil {
		return "", fmt.Errorf("creating tun interface: %w", err)
	}
	osName, err := tdev.Name()
	if err != nil {
		_ = tdev.Close()
		return "", fmt.Errorf("naming tun interface: %w", err)
	}
	logger := &wgdev.Logger{
		Verbosef: func(format string, args ...any) {
			slog.Debug("wireguard: "+fmt.Sprintf(format, args...), "iface", name)
		},
		Errorf: func(format string, args ...any) {
			slog.Error("wireguard: "+fmt.Sprintf(format, args...), "iface", name)
		},
	}
	dev := wgdev.NewDevice(tdev, conn.NewDefaultBind(), logger) // closes tdev with it
	ln, err := listen(name)
	if err != nil {
		dev.Close()
		return "", fmt.Errorf("opening the wireguard control socket: %w", err)
	}
	if err := published(name, osName); err != nil {
		_ = ln.Close()
		dev.Close()
		return "", err
	}
	go serveUAPI(ln, dev)
	u.dev, u.uapi, u.osName = dev, ln, osName
	return osName, nil
}

// serveUAPI answers wgctrl on the control socket until it is closed. The
// device brings itself up and down with the interface, so nothing else is
// needed here.
func serveUAPI(ln net.Listener, dev *wgdev.Device) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go dev.IpcHandle(c)
	}
}

// Delete stops the device, which removes the tun interface and the control
// socket. A device that is not running is not an error.
func (u *userspaceDevice) Delete(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dev == nil {
		return nil
	}
	u.stop()
	return unpublished(name)
}

func (u *userspaceDevice) stop() {
	_ = u.uapi.Close()
	u.dev.Close()
	u.dev, u.uapi, u.osName = nil, nil, ""
}
