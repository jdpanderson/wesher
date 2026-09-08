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
		want    key
		wantErr string
	}{
		{"valid key", encoded, raw, ""},
		{"empty input", "", key{}, ""},
		{"wrong length", "YWJj", nil, "unsupported cluster key length"},
		{"invalid base64", "not*base64!", nil, "illegal base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var k key
			err := k.UnmarshalText([]byte(tt.in))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, k)
		})
	}
}
