package enroll

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_codec(t *testing.T) {
	in := Welcome{GossipAddr: "192.0.2.1:7946"}
	b, err := marshal(in)
	require.NoError(t, err)
	var out Welcome
	require.NoError(t, unmarshal(b, &out))
	assert.Equal(t, in.GossipAddr, out.GossipAddr)
	assert.Error(t, unmarshal([]byte("{"), &out))
}
