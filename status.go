package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/costela/wesher/cluster"
	"github.com/costela/wesher/wg"
)

// StatusCmd shows the live wireguard state of a wesher interface, naming peers
// from the persisted cluster state. Needs the same privileges as the agent.
type StatusCmd struct {
	Interface string `env:"WESHER_INTERFACE" help:"wireguard interface to report on" default:"wgoverlay"`
	JSON      bool   `help:"print the report as JSON"`
}

func (c *StatusCmd) Run() error {
	report, err := wg.Status(c.Interface)
	if err != nil {
		return err
	}
	names := make(map[string]string) // public key -> node name
	for _, n := range cluster.KnownNodes(c.Interface) {
		names[n.PubKey] = n.Name
	}
	if c.JSON {
		return renderStatusJSON(os.Stdout, report, names)
	}
	return renderStatus(os.Stdout, report, names, time.Now())
}

// namedPeer is a PeerReport with the node name from the cluster state, for JSON output.
type namedPeer struct {
	Name string `json:"name,omitempty"`
	wg.PeerReport
}

func renderStatusJSON(w io.Writer, r *wg.Report, names map[string]string) error {
	out := struct {
		*wg.Report
		Peers []namedPeer `json:"peers"`
	}{Report: r, Peers: make([]namedPeer, 0, len(r.Peers))}
	for _, p := range r.Peers {
		out.Peers = append(out.Peers, namedPeer{Name: names[p.PublicKey], PeerReport: p})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderStatus(w io.Writer, r *wg.Report, names map[string]string, now time.Time) error {
	addrs := make([]string, 0, len(r.Addrs))
	for _, a := range r.Addrs {
		addrs = append(addrs, a.String())
	}
	if _, err := fmt.Fprintf(w, "interface: %s\naddress:   %s\nport:      %d\npubkey:    %s\npeers:     %d\n",
		r.Interface, strings.Join(addrs, " "), r.ListenPort, r.PublicKey, len(r.Peers)); err != nil {
		return err
	}
	if len(r.Peers) == 0 {
		return nil
	}

	peers := append([]wg.PeerReport(nil), r.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		return peerName(peers[i], names) < peerName(peers[j], names)
	})

	// tabwriter reports write errors from Flush, so the per-row results are dropped.
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nNAME\tOVERLAY\tENDPOINT\tHANDSHAKE\tRX\tTX")
	for _, p := range peers {
		overlay := "-"
		if a, ok := p.OverlayAddr(); ok {
			overlay = a.String()
		}
		endpoint := p.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			peerName(p, names), overlay, endpoint, handshakeAge(p.LastHandshake, now),
			humanBytes(p.ReceiveBytes), humanBytes(p.TransmitBytes))
	}
	return tw.Flush()
}

// peerName is the node name from the cluster state, else a shortened public key.
func peerName(p wg.PeerReport, names map[string]string) string {
	if name, ok := names[p.PublicKey]; ok && name != "" {
		return name
	}
	if len(p.PublicKey) > 12 {
		return p.PublicKey[:12] + "..."
	}
	return p.PublicKey
}

func handshakeAge(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return now.Sub(t).Truncate(time.Second).String() + " ago"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 4 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
