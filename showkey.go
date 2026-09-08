package main

import (
	"encoding/base64"
	"fmt"

	"github.com/jdpanderson/wesher/cluster"
)

// ShowKeyCmd prints the persisted cluster key, for nodes started without a terminal.
type ShowKeyCmd struct {
	Interface string `env:"WESHER_INTERFACE" help:"wireguard interface whose cluster key to print" default:"wgoverlay"`
}

func (c *ShowKeyCmd) Run() error {
	key, err := cluster.LoadKey(c.Interface)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key))
	return nil
}
