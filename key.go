package main

import (
	"encoding"
	"encoding/base64"
	"fmt"

	"github.com/costela/wesher/cluster"
)

// key is a base64-encoded cluster key flag; empty means "generate one".
type key []byte

var _ encoding.TextUnmarshaler = (*key)(nil)

func (k *key) UnmarshalText(in []byte) error {
	decoded, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		return err
	}
	if len(decoded) != 0 && len(decoded) != cluster.KeyLen {
		return fmt.Errorf("unsupported cluster key length; expected %d, got %d", cluster.KeyLen, len(decoded))
	}
	*k = decoded
	return nil
}
