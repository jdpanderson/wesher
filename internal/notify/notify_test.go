package notify

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_None(t *testing.T) {
	var n Notifier = None{}
	assert.NoError(t, n.Ready("x"))
	assert.NoError(t, n.Status("x"))
	assert.NoError(t, n.Stopping())
}

func Test_Default(t *testing.T) {
	assert.NotNil(t, Default())
}
