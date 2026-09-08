package wg

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/costela/wesher/common"
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
func (f *fakeNL) LinkSetMTU(netlink.Link, int) error            { return f.call("LinkSetMTU") }
func (f *fakeNL) LinkSetUp(netlink.Link) error                  { return f.call("LinkSetUp") }
func (f *fakeNL) RouteAdd(r *netlink.Route) error {
	if err := f.call("RouteAdd"); err != nil {
		return err
	}
	f.routes = append(f.routes, r)
	return nil
}

type fakeWG struct {
	cfgErr error
	cfg    *wgtypes.Config
}

func (f *fakeWG) Device(string) (*wgtypes.Device, error) { return &wgtypes.Device{}, nil }
func (f *fakeWG) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	f.cfg = &cfg
	return f.cfgErr
}

func newFakeState(t *testing.T, nl *fakeNL, wgc *fakeWG) *State {
	t.Helper()
	s, _, err := newState("wgtest0", 51820, netip.MustParsePrefix(testPrefix), "test", wgc, nl)
	require.NoError(t, err)
	return s
}

func Test_State_SetUpInterface_fake(t *testing.T) {
	nl := &fakeNL{}
	wgc := &fakeWG{}
	s := newFakeState(t, nl, wgc)

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	require.NoError(t, s.SetUpInterface([]common.Node{p1}))

	assert.Equal(t, []string{"LinkAdd", "LinkByName", "AddrReplace", "LinkSetMTU", "LinkSetUp", "RouteAdd"}, nl.calls)
	assert.Equal(t, "wireguard", nl.link.Type())
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
	require.NoError(t, s.SetUpInterface([]common.Node{testPeer(t, "p1", "192.0.2.1", "10.99.0.1")}))
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeState(t, &fakeNL{errs: tt.nlErrs}, &fakeWG{cfgErr: tt.cfgErr})
			err := s.SetUpInterface([]common.Node{testPeer(t, "p1", "192.0.2.1", "10.99.0.1")})
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
