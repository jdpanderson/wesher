package etchosts

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEtcHosts_writeEntryWithBanner(t *testing.T) {
	type args struct {
		banner string
		ip     string
		names  []string
	}

	eh := &EtcHosts{}

	tests := []struct {
		name    string
		args    args
		wantTmp string
		wantErr bool
	}{
		{"do not write empty ip", args{DefaultBanner, "", []string{"somename", "someothername"}}, "", false},
		{"do not write empty names", args{DefaultBanner, "1.2.3.4", []string{}}, "", false},
		{"complete entry", args{DefaultBanner, "1.2.3.4", []string{"somename", "someothername"}}, fmt.Sprintf("1.2.3.4\tsomename someothername\t%s\n", DefaultBanner), false},
		{"custom banner", args{"# somebanner", "1.2.3.4", []string{"somename", "someothername"}}, fmt.Sprintf("1.2.3.4\tsomename someothername\t%s\n", "# somebanner"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := &bytes.Buffer{}
			if err := eh.writeEntryWithBanner(tmp, tt.args.banner, tt.args.ip, tt.args.names); (err != nil) != tt.wantErr {
				t.Errorf("writeEntryWithBanner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotTmp := tmp.String(); gotTmp != tt.wantTmp {
				t.Errorf("writeEntryWithBanner() got:\n%#v, want\n%#v", gotTmp, tt.wantTmp)
			}
		})
	}
}

func TestEtcHosts_writeEntries(t *testing.T) {
	type fields struct {
		Banner string
		Path   string
		Logger logrus.StdLogger
	}
	type args struct {
		orig       io.Reader
		ipsToNames map[string][]string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantDest string
		wantErr  bool
	}{
		{
			"simple empty write",
			fields{},
			args{strings.NewReader(""), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
			false,
		},
		{
			"do not touch comments",
			fields{},
			args{strings.NewReader("# some comment\n"), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"# some comment\n1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
			false,
		},
		{
			"do not touch existing entries",
			fields{},
			args{strings.NewReader("4.3.2.1 hostname1 hostname2\n"), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"4.3.2.1 hostname1 hostname2\n1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
			false,
		},
		{
			"remove managed entry not in map",
			fields{},
			args{strings.NewReader("4.3.2.1 fooz baarz # ! MANAGED AUTOMATICALLY !\n"), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
			false,
		},
		{
			"custom banner",
			fields{Banner: "# somebanner"},
			args{strings.NewReader(""), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"1.2.3.4\tfoo bar\t# somebanner\n",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eh := &EtcHosts{
				Banner: tt.fields.Banner,
				Path:   tt.fields.Path,
				Logger: tt.fields.Logger,
			}
			dest := &bytes.Buffer{}
			if err := eh.writeEntries(tt.args.orig, dest, tt.args.ipsToNames); (err != nil) != tt.wantErr {
				t.Errorf("EtcHosts.writeEntries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotDest := dest.String(); gotDest != tt.wantDest {
				t.Errorf("EtcHosts.writeEntries() = '%#v', want '%#v'", gotDest, tt.wantDest)
			}
		})
	}
}

func writeTempHosts(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	require.NoError(t, os.WriteFile(p, []byte(content), mode))
	return p
}

func TestEtcHosts_WriteEntries(t *testing.T) {
	const banner = "# ! test banner"
	tests := []struct {
		name string
		orig string
		ips  map[string][]string
		want string
	}{
		{
			"add to empty file",
			"",
			map[string][]string{"10.0.0.1": {"a"}},
			"10.0.0.1\ta\t" + banner + "\n",
		},
		{
			"preserve unmanaged and update managed",
			"127.0.0.1 localhost\n10.0.0.1\told\t" + banner + "\n",
			map[string][]string{"10.0.0.1": {"new"}},
			"127.0.0.1 localhost\n10.0.0.1\tnew\t" + banner + "\n",
		},
		{
			"remove managed entries with empty map",
			"127.0.0.1 localhost\n10.0.0.1\ta\t" + banner + "\n",
			map[string][]string{},
			"127.0.0.1 localhost\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeTempHosts(t, tt.orig, 0o600)
			eh := &EtcHosts{Banner: banner, Path: p, Logger: logrus.StandardLogger()}
			require.NoError(t, eh.WriteEntries(tt.ips))

			got, err := os.ReadFile(p)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestEtcHosts_WriteEntries_preservesMode(t *testing.T) {
	p := writeTempHosts(t, "", 0o640)
	eh := &EtcHosts{Path: p}
	require.NoError(t, eh.WriteEntries(map[string][]string{"10.0.0.1": {"a"}}))

	info, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestEtcHosts_WriteEntries_nilLogger(t *testing.T) {
	p := writeTempHosts(t, "", 0o600)
	eh := &EtcHosts{Path: p}
	require.NoError(t, eh.WriteEntries(map[string][]string{"10.0.0.1": {"a"}}))
}

func TestEtcHosts_WriteEntries_missingFile(t *testing.T) {
	eh := &EtcHosts{Path: filepath.Join(t.TempDir(), "nonexistent")}
	err := eh.WriteEntries(map[string][]string{"10.0.0.1": {"a"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not open")
}

func TestEtcHosts_WriteEntries_noLeftoverTempFile(t *testing.T) {
	p := writeTempHosts(t, "", 0o600)
	eh := &EtcHosts{Path: p}
	entries := map[string][]string{"10.0.0.1": {"a"}}
	require.NoError(t, eh.WriteEntries(entries))

	// no leftover tempfiles next to the hosts file
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(p), "etchosts*"))
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestEtcHosts_WriteEntries_renameFallback(t *testing.T) {
	for _, logger := range []logrus.StdLogger{nil, logrus.StandardLogger()} {
		orig := "127.0.0.1 localhost\n10.0.0.1\told\t" + DefaultBanner + "\n"
		p := writeTempHosts(t, orig, 0o600)
		eh := &EtcHosts{Path: p, Logger: logger, rename: func(_, _ string) error {
			return errors.New("cross-device link")
		}}
		require.NoError(t, eh.WriteEntries(map[string][]string{}))

		got, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1 localhost\n", string(got), "copy fallback must truncate")
	}
}
