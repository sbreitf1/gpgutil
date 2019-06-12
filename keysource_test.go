package gpgutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileKeySourceObj(t *testing.T) {
	src := KeySource{File: "/some/file", Passphrase: "secret"}
	assert.True(t, src.HasValue())
	assert.True(t, src.IsFileSource())
	assert.False(t, src.IsNamedSource())
	assert.Equal(t, "/some/file", src.String())
}

func TestNamedKeySourceObj(t *testing.T) {
	src := KeySource{Owner: "sbreitf1@web.de", Passphrase: "secret"}
	assert.True(t, src.HasValue())
	assert.False(t, src.IsFileSource())
	assert.True(t, src.IsNamedSource())
	assert.Equal(t, "sbreitf1@web.de", src.String())
}

func TestMakeEmptyKeySourceObj(t *testing.T) {
	src := MakeEmptyKeySource()
	assert.False(t, src.HasValue())
	assert.False(t, src.IsFileSource())
	assert.False(t, src.IsNamedSource())
	assert.Equal(t, "{EMPTY}", src.String())
}
