package gpgutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/sbreitf1/errors"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	inFile := tmp.File()
	encFile := tmp.File()
	decFile := tmp.File()

	content := []byte("foo bar")
	ioutil.WriteFile(inFile, content, os.ModePerm)

	assert.NoError(t, EncryptFile(inFile, encFile, MakeFileKeySource(res("user1-pub.asc"), "")))
	assert.NoError(t, DecryptFile(encFile, decFile, MakeFileKeySource(res("user1-priv.asc"), "test")))

	data, err := ioutil.ReadFile(decFile)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, content, data)
}

func TestEncryptNoKey(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	inFile := tmp.File()
	encFile := tmp.File()

	content := []byte("foo bar")
	ioutil.WriteFile(inFile, content, os.ModePerm)

	err := EncryptFile(inFile, encFile, MakeEmptyKeySource())
	assertError(t, ErrNoKeySpecified, err)
}

func TestEncryptInvalidFile(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	encFile := tmp.File()

	err := EncryptFile(res("totallynonexisting"), encFile, MakeFileKeySource(res("user1-priv.asc"), "test"))
	assertError(t, ErrTechnicalProblem, err)
}

func TestEncryptInvalidKey(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	inFile := tmp.File()
	encFile := tmp.File()

	content := []byte("foo bar")
	ioutil.WriteFile(inFile, content, os.ModePerm)

	err := EncryptFile(inFile, encFile, MakeFileKeySource(res("non-existing-key.asc"), "test"))
	assertError(t, ErrTechnicalProblem, err)
}

func TestDecrypt(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	assert.NoError(t, DecryptFile(res("testdata-enc1.gpg"), decFile, MakeFileKeySource(res("user1-priv.asc"), "test")))

	data, err := ioutil.ReadFile(decFile)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, "foo bar", string(data))
}

func TestDecryptWrongKeyPassphrase(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	err := DecryptFile(res("testdata-enc1.gpg"), decFile, MakeFileKeySource(res("user1-priv.asc"), "wrongpass"))
	assertError(t, ErrDecryptKeyFailed, err)
}

func TestDecryptWrongKey(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	err := DecryptFile(res("testdata-enc1.gpg"), decFile, MakeFileKeySource(res("user2-priv.asc"), "asdf"))
	assertError(t, ErrWrongKey, err)
}

func TestDecryptPublicKey(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	err := DecryptFile(res("testdata-enc1.gpg"), decFile, MakeFileKeySource(res("user2-pub.asc"), ""))
	assertError(t, ErrNoPrivateKey, err)
}

func TestEncryptSignDecryptCheck(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	inFile := tmp.File()
	encFile := tmp.File()
	decFile := tmp.File()

	content := []byte("foo bar")
	ioutil.WriteFile(inFile, content, os.ModePerm)

	assert.NoError(t, EncryptAndSignFile(inFile, encFile, MakeFileKeySource(res("user1-pub.asc"), ""), MakeFileKeySource(res("user2-priv.asc"), "asdf")))
	assert.NoError(t, DecryptFileAndCheckSignature(encFile, decFile, MakeFileKeySource(res("user1-priv.asc"), "test"), MakeFileKeySource(res("user2-pub.asc"), "")))

	data, err := ioutil.ReadFile(decFile)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, "foo bar", string(data))
}

func TestDecryptCheck(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	assert.NoError(t, DecryptFileAndCheckSignature(res("testdata-enc1-sig2.gpg"), decFile, MakeFileKeySource(res("user1-priv.asc"), "test"), MakeFileKeySource(res("user2-pub.asc"), "")))

	data, err := ioutil.ReadFile(decFile)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, "foo bar", string(data))
}

func TestDecryptCheckWrongSigner(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	err := DecryptFileAndCheckSignature(res("testdata-enc1-sig2.gpg"), decFile, MakeFileKeySource(res("user1-priv.asc"), "test"), MakeFileKeySource(res("user3-pub.asc"), ""))
	assertError(t, ErrWrongSignatureVerificationKey, err)
}

func TestDecryptCheckMissingSignature(t *testing.T) {
	tmp := newTempProvider()
	defer tmp.Close()
	decFile := tmp.File()

	err := DecryptFileAndCheckSignature(res("testdata-enc1.gpg"), decFile, MakeFileKeySource(res("user1-priv.asc"), "test"), MakeFileKeySource(res("user3-pub.asc"), ""))
	assertError(t, ErrMissingSignature, err)
}

func assertError(t *testing.T, expected interface{}, actual error, msgAndArgs ...interface{}) bool {
	switch e := expected.(type) {
	case errors.Template:
		return assert.True(t, errors.InstanceOf(actual, e), "Expected error %q but got %q instead", e.GetType(), getErrMsg(actual))
	case errors.Error:
		return assert.True(t, errors.AreEqual(actual, e), "Expected error %q but got %q instead", e.GetType(), getErrMsg(actual))
	default:
		panic(fmt.Sprintf("Expected error cannot be of type %T", expected))
	}
}

func getErrMsg(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func res(path string) string {
	return "./test/" + path
}

type tempProvider struct {
	files []string
}

func newTempProvider() *tempProvider {
	return &tempProvider{make([]string, 0)}
}

func (t *tempProvider) File() string {
	f, err := ioutil.TempFile("", "gpgutil-test-*")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	t.files = append(t.files, f.Name())
	return f.Name()
}

func (t *tempProvider) Close() {
	for _, file := range t.files {
		os.Remove(file)
	}
}
