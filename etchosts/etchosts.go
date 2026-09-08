package etchosts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// DefaultBanner is the default magic comment used to identify entries managed by etchosts
const DefaultBanner = "# ! MANAGED AUTOMATICALLY !"

// DefaultPath is the default path used to write hosts entries
const DefaultPath = "/etc/hosts"

// EtcHosts contains the options used to write hosts entries.
// The zero value can be used to write to DefaultPath using DefaultBanner as a marker.
type EtcHosts struct {
	// Banner is the magic comment used to identify entries managed by etchosts; if not set, will use DefaultBanner.
	// It must start with "#" to mark it as a comment.
	Banner string
	// Path is the path to the /etc/hosts file; if not set, will use DefaultPath.
	Path string
	// Logger is optional; nil disables logging.
	Logger *slog.Logger

	// rename replaces the hosts file with the temp file; nil means os.Rename.
	rename func(oldpath, newpath string) error
}

// log writes at the given level if a Logger is set.
func (eh *EtcHosts) log(level slog.Level, msg string, args ...any) {
	if eh.Logger != nil {
		eh.Logger.Log(context.Background(), level, msg, args...)
	}
}

// WriteEntries is used to write the hosts entries to EtcHosts.Path
// Each IP address with their (potentially multiple) hostnames are written to a line marked with EtcHosts.Banner, to
// avoid overwriting preexisting entries.
func (eh *EtcHosts) WriteEntries(ipsToNames map[string][]string) error {
	hostsPath := eh.Path
	if hostsPath == "" {
		hostsPath = DefaultPath
	}

	// We do not want to create the hosts file; if it's not there, we probably have the wrong path.
	etcHosts, err := os.OpenFile(hostsPath, os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("could not open %s for reading: %w", hostsPath, err)
	}
	defer etcHosts.Close()

	// Temp file in the same directory so the rename is atomic. A library like renameio
	// would not do: /etc/hosts is a bind mount in containers and needs the copy fallback below.
	tmp, err := os.CreateTemp(filepath.Dir(hostsPath), "etchosts")
	if err != nil {
		return fmt.Errorf("could not create tempfile: %w", err)
	}

	// remove tempfile; this might fail if we managed to move it, which is ok
	defer func(file *os.File) {
		file.Close()
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			eh.log(slog.LevelWarn, "could not remove temp file", "path", file.Name(), "err", err)
		}
	}(tmp)

	if err := eh.writeEntries(etcHosts, tmp, ipsToNames); err != nil {
		return err
	}

	return eh.movePreservePerms(tmp, etcHosts)
}

// writeEntries copies orig to dest, rewriting managed lines whose IP is in
// ipsToNames, dropping the other managed lines, and appending new entries.
// Write errors surface once, on the final Flush.
func (eh *EtcHosts) writeEntries(orig io.Reader, dest io.Writer, ipsToNames map[string][]string) error {
	banner := eh.Banner
	if banner == "" {
		banner = DefaultBanner
	}
	w := bufio.NewWriter(dest)
	written := make(map[string]bool, len(ipsToNames))

	scanner := bufio.NewScanner(orig)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasSuffix(strings.TrimSpace(line), strings.TrimSpace(banner)) {
			fmt.Fprintln(w, line) // unmanaged line, keep as is
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		ip := tokens[0]
		if names, ok := ipsToNames[ip]; ok && !written[ip] {
			eh.writeEntryWithBanner(w, banner, ip, names)
			written[ip] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading hosts file: %w", err)
	}

	for ip, names := range ipsToNames {
		if !written[ip] {
			eh.writeEntryWithBanner(w, banner, ip, names)
		}
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("error writing hosts file: %w", err)
	}
	return nil
}

func (eh *EtcHosts) writeEntryWithBanner(w *bufio.Writer, banner, ip string, names []string) {
	if ip == "" || len(names) == 0 {
		return
	}
	eh.log(slog.LevelDebug, "writing hosts entry", "ip", ip, "names", names)
	fmt.Fprintf(w, "%s\t%s\t%s\n", ip, strings.Join(names, " "), banner)
}

func (eh *EtcHosts) movePreservePerms(src, dst *os.File) error {
	if err := src.Sync(); err != nil {
		return fmt.Errorf("could not sync changes to %s: %w", src.Name(), err)
	}

	etcHostsInfo, err := dst.Stat()
	if err != nil {
		return fmt.Errorf("could not stat %s: %w", dst.Name(), err)
	}
	// CreateTemp made src 0600; match the hosts file before it becomes the hosts file
	if err := src.Chmod(etcHostsInfo.Mode()); err != nil {
		return fmt.Errorf("could not chmod %s: %w", src.Name(), err)
	}

	rename := eh.rename
	if rename == nil {
		rename = os.Rename
	}
	if err = rename(src.Name(), dst.Name()); err != nil {
		eh.log(slog.LevelInfo, "could not rename over hosts file, falling back to copy", "path", dst.Name(), "err", err)

		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := dst.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := dst.Truncate(0); err != nil {
			return err
		}
		_, err = io.Copy(dst, src)
		return err
	}
	// TODO: also keep user?

	return nil
}
