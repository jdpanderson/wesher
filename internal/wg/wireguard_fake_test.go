package wg

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakeNL records netlink calls; errs injects an error per method name.
type fakeNL struct {
	errs   map[string]error
	calls  []string
	link   netlink.Link
	mtu    int
	addrs  []netlink.Addr
	routes []*netlink.Route
}

func (f *fakeNL) call(name string) error {
	f.calls = append(f.calls, name)
	return f.errs[name]
}

func (f *fakeNL) LinkAdd(l netlink.Link) error {
	if err := f.call("LinkAdd"); err != nil {
		return err
	}
	f.link = l
	return nil
}
func (f *fakeNL) LinkDel(netlink.Link) error { return f.call("LinkDel") }
func (f *fakeNL) LinkByName(string) (netlink.Link, error) {
	if err := f.call("LinkByName"); err != nil {
		return nil, err
	}
	return &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wgtest0", Index: 7}}, nil
}
func (f *fakeNL) AddrReplace(netlink.Link, *netlink.Addr) error { return f.call("AddrReplace") }
func (f *fakeNL) LinkSetMTU(_ netlink.Link, mtu int) error      { f.mtu = mtu; return f.call("LinkSetMTU") }
func (f *fakeNL) LinkSetUp(netlink.Link) error                  { return f.call("LinkSetUp") }
func (f *fakeNL) RouteAdd(r *netlink.Route) error {
	if err := f.call("RouteAdd"); err != nil {
		return err
	}
	for _, have := range f.routes {
		if have.Dst.String() == r.Dst.String() {
			return os.ErrExist
		}
	}
	f.routes = append(f.routes, r)
	return nil
}
func (f *fakeNL) RouteDel(r *netlink.Route) error {
	if err := f.call("RouteDel"); err != nil {
		return err
	}
	kept := f.routes[:0]
	for _, have := range f.routes {
		if have.Dst.String() != r.Dst.String() {
			kept = append(kept, have)
		}
	}
	f.routes = kept
	return nil
}
func (f *fakeNL) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	if err := f.call("AddrList"); err != nil {
		return nil, err
	}
	return f.addrs, nil
}
func (f *fakeNL) RouteList(netlink.Link, int) ([]netlink.Route, error) {
	if err := f.call("RouteList"); err != nil {
		return nil, err
	}
	out := make([]netlink.Route, len(f.routes))
	for i, r := range f.routes {
		out[i] = *r
	}
	return out, nil
}

type fakeWG struct {
	cfgErr    error
	cfg       *wgtypes.Config
	device    *wgtypes.Device // returned by Device when set
	deviceErr error
}

func (f *fakeWG) Device(string) (*wgtypes.Device, error) {
	if f.deviceErr != nil {
		return nil, f.deviceErr
	}
	if f.device != nil {
		return f.device, nil
	}
	return &wgtypes.Device{}, nil
}
func (f *fakeWG) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	f.cfg = &cfg
	return f.cfgErr
}

func newFakeState(t *testing.T, nl *fakeNL, wgc *fakeWG) *State {
	t.Helper()
	s, err := newState(testConfig(), wgc, nl)
	require.NoError(t, err)
	return s
}

func Test_State_SetUpInterface_fake(t *testing.T) {
	nl := &fakeNL{}
	wgc := &fakeWG{}
	s := newFakeState(t, nl, wgc)

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))

	assert.Equal(t, []string{"LinkAdd", "LinkByName", "AddrReplace", "LinkSetMTU", "LinkSetUp", "RouteAdd", "RouteList"}, nl.calls)
	assert.Equal(t, "wireguard", nl.link.Type())
	assert.Equal(t, 1400, nl.mtu)
	require.NotNil(t, wgc.cfg)
	assert.True(t, wgc.cfg.ReplacePeers)
	assert.Equal(t, 51820, *wgc.cfg.ListenPort)
	assert.Len(t, wgc.cfg.Peers, 1)
	require.Len(t, nl.routes, 1)
	assert.Equal(t, 7, nl.routes[0].LinkIndex)
	assert.Equal(t, "10.99.0.1/32", nl.routes[0].Dst.String())
	assert.Equal(t, netlink.SCOPE_LINK, nl.routes[0].Scope)
}

func Test_State_SetUpInterface_fake_existingTolerated(t *testing.T) {
	nl := &fakeNL{errs: map[string]error{"LinkAdd": os.ErrExist, "RouteAdd": os.ErrExist}}
	s := newFakeState(t, nl, &fakeWG{})
	require.NoError(t, s.SetUpInterface([]overlay.Node{testPeer(t, "p1", "192.0.2.1", "10.99.0.1")}))
}

func Test_State_SetUpInterface_fake_removesStaleRoutes(t *testing.T) {
	nl := &fakeNL{}
	s := newFakeState(t, nl, &fakeWG{})
	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	p2 := testPeer(t, "p2", "192.0.2.2", "10.99.0.2")

	p1.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}

	// leftovers on the interface from a previous run, and the kernel's route to our own address
	_, foreign, _ := net.ParseCIDR("192.0.2.9/32")
	_, wide, _ := net.ParseCIDR("10.99.0.0/24")
	nl.routes = append(nl.routes, &netlink.Route{Dst: foreign}, &netlink.Route{Dst: wide}, &netlink.Route{Dst: addrToIPNet(s.overlayAddr)}, &netlink.Route{Dst: nil})

	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))
	dsts := func() []string {
		out := make([]string, 0, len(nl.routes))
		for _, r := range nl.routes {
			out = append(out, r.Dst.String())
		}
		return out
	}
	assert.ElementsMatch(t, []string{"<nil>", s.overlayAddr.String() + "/32", "10.99.0.1/32", "192.168.7.0/24", "10.99.0.2/32"}, dsts(),
		"routes nobody advertises are removed, routes without a destination are left alone")

	nl.calls = nil
	require.NoError(t, s.SetUpInterface([]overlay.Node{p2}))
	assert.Contains(t, nl.calls, "RouteDel")
	assert.ElementsMatch(t, []string{"<nil>", s.overlayAddr.String() + "/32", "10.99.0.2/32"}, dsts(), "p1's address and network went with it")

	// route del failure is reported
	nl.errs = map[string]error{"RouteDel": errors.New("boom")}
	err := s.SetUpInterface(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "removing route")
}

func Test_State_SetUpInterface_fake_errors(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		nlErrs  map[string]error
		cfgErr  error
		wantMsg string
	}{
		{"link add", map[string]error{"LinkAdd": boom}, nil, "creating link"},
		{"configure device", nil, boom, "setting wireguard configuration"},
		{"link by name", map[string]error{"LinkByName": boom}, nil, "getting link information"},
		{"addr replace", map[string]error{"AddrReplace": boom}, nil, "setting address"},
		{"mtu", map[string]error{"LinkSetMTU": boom}, nil, "setting MTU"},
		{"link up", map[string]error{"LinkSetUp": boom}, nil, "enabling interface"},
		{"route add", map[string]error{"RouteAdd": boom}, nil, "adding route"},
		{"route list", map[string]error{"RouteList": boom}, nil, "listing routes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeState(t, &fakeNL{errs: tt.nlErrs}, &fakeWG{cfgErr: tt.cfgErr})
			err := s.SetUpInterface([]overlay.Node{testPeer(t, "p1", "192.0.2.1", "10.99.0.1")})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.ErrorIs(t, err, boom)
		})
	}
}

func Test_State_DownInterface_fake(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name      string
		nlErrs    map[string]error
		wantErr   string
		wantCalls []string
	}{
		{"happy path", nil, "", []string{"LinkByName", "LinkDel"}},
		{"link gone is a no-op", map[string]error{"LinkByName": netlink.LinkNotFoundError{}}, "", []string{"LinkByName"}},
		{"link by name error", map[string]error{"LinkByName": boom}, "getting link", []string{"LinkByName"}},
		{"link del error", map[string]error{"LinkDel": boom}, "boom", []string{"LinkByName", "LinkDel"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nl := &fakeNL{errs: tt.nlErrs}
			s := newFakeState(t, nl, &fakeWG{})
			err := s.DownInterface()
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
			assert.Equal(t, tt.wantCalls, nl.calls)
		})
	}
}
