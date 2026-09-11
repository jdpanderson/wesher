package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/jdpanderson/cheesecloth/wg"
)

// Text and JSON rendering of a status report.

// namedPeer is a PeerReport with what the cluster state knows, for JSON output.
type namedPeer struct {
	peerInfo
	wg.PeerReport
}

func renderStatusJSON(w io.Writer, r *wg.Report, local trust.PublicKey, names map[string]peerInfo) error {
	out := struct {
		*wg.Report
		Identity string      `json:"identity,omitempty"`
		Peers    []namedPeer `json:"peers"`
	}{Report: r, Peers: make([]namedPeer, 0, len(r.Peers))}
	if local != (trust.PublicKey{}) {
		out.Identity = local.String()
	}
	for _, p := range r.Peers {
		out.Peers = append(out.Peers, namedPeer{peerInfo: names[p.PublicKey], PeerReport: p})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderStatus(w io.Writer, r *wg.Report, local trust.PublicKey, names map[string]peerInfo, now time.Time) error {
	addrs := make([]string, 0, len(r.Addrs))
	for _, a := range r.Addrs {
		addrs = append(addrs, a.String())
	}
	identity := "-"
	if local != (trust.PublicKey{}) {
		identity = local.String()
	}
	if _, err := fmt.Fprintf(w, "interface: %s\naddress:   %s\nport:      %d\npubkey:    %s\nidentity:  %s\npeers:     %d\n",
		r.Interface, strings.Join(addrs, " "), r.ListenPort, r.PublicKey, identity, len(r.Peers)); err != nil {
		return err
	}
	if len(r.Peers) == 0 {
		return nil
	}

	peers := slices.Clone(r.Peers)
	slices.SortFunc(peers, func(a, b wg.PeerReport) int { return strings.Compare(peerName(a, names), peerName(b, names)) })

	// tabwriter reports write errors from Flush, so the per-row results are dropped.
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nNAME\tIDENTITY\tOVERLAY\tENDPOINT\tHANDSHAKE\tRX\tTX\tROUTES")
	for _, p := range peers {
		info := names[p.PublicKey]
		endpoint := p.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		identity := "-"
		if info.Identity != nil {
			identity = info.Identity.Short()
		}
		// the cluster state says which allowed IP is the peer's own address; the rest are routes
		overlay := "-"
		rs := p.AllowedIPs
		if info.Overlay.IsValid() {
			overlay = info.Overlay.String()
			rs = slices.DeleteFunc(slices.Clone(rs), func(x netip.Prefix) bool { return x.IsSingleIP() && x.Addr() == info.Overlay })
		}
		routes := "-"
		if len(rs) > 0 {
			strs := make([]string, len(rs))
			for i, r := range rs {
				strs[i] = r.String()
			}
			routes = strings.Join(strs, ",")
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			peerName(p, names), identity, overlay, endpoint, handshakeAge(p.LastHandshake, now),
			humanBytes(p.ReceiveBytes), humanBytes(p.TransmitBytes), routes)
	}
	return tw.Flush()
}

// peerName is the node name from the cluster state, else a shortened public key.
func peerName(p wg.PeerReport, names map[string]peerInfo) string {
	if info, ok := names[p.PublicKey]; ok && info.Name != "" {
		return info.Name
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
