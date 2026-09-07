package main

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_key_UnmarshalText(t *testing.T) {
	raw := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
	encoded := base64.StdEncoding.EncodeToString(raw)

	tests := []struct {
		name    string
		in      string
		want    []byte
		wantErr bool
	}{
		{"valid key", encoded, raw, false},
		{"empty input", "", []byte{}, false},
		{"short key decodes without length check", "YWJj", []byte("abc"), false},
		{"invalid base64", "not*base64!", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &key{}
			err := k.UnmarshalText([]byte(tt.in))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, k.bytes)
		})
	}
}
