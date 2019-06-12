package gpgutil

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/sbreitf1/errors"
	"golang.org/x/crypto/openpgp"
)

var (
	// ErrTechnicalProblem occurs on all errors not related to cryptography.
	ErrTechnicalProblem = errors.New("Technical error")
	// ErrNoKeySpecified occurs when a mandatory key is not specified.
	ErrNoKeySpecified = errors.New("No key specified")
	// ErrKeySourceNotAccepted occurs on importing a disabled key source (See gpgutil.AcceptFileKeySources and gpgutil.AcceptNamedKeySources)
	ErrKeySourceNotAccepted = errors.New("Key source %q not accepted")
	// ErrImportKeyFailed occurs when a specified key could not be imported.
	ErrImportKeyFailed = errors.New("Failed to import key")
	// ErrDecryptKeyFailed occurs when a specified key was imported but could not be decrypted.
	ErrDecryptKeyFailed = errors.New("Failed to decrypt key")
	// ErrGPG occurs on all cryptography related errors.
	ErrGPG = errors.New("A cryptographic method failed")
)

var (
	// GPGCommand can be used to override the command to execute gpg on this machine.
	GPGCommand string
	// AcceptFileKeySources determines whether file key sources are accepted.
	AcceptFileKeySources bool
	// AcceptNamedKeySources determines whether named key sources are accepted.
	AcceptNamedKeySources bool
)

func init() {
	GPGCommand = "gpg"
	AcceptFileKeySources = true
	AcceptNamedKeySources = true
}

// EncryptAndSignFile encrypts and signs the given file using the given GPG keys and applies GZIP compression.
func EncryptAndSignFile(inFile, outFile string, encryptKeySrc KeySource, signKeySrc KeySource) errors.Error {
	if !signKeySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No signing key specified").Make()
	}
	return encryptAndSignFile(inFile, outFile, encryptKeySrc, signKeySrc)
}

// EncryptFile encrypts the given file using the given GPG keys and applies GZIP compression.
func EncryptFile(inFile, outFile string, encryptKeySrc KeySource) errors.Error {
	return encryptAndSignFile(inFile, outFile, encryptKeySrc, MakeEmptyKeySource())
}

func encryptAndSignFile(inFile, outFile string, encryptKeySrc KeySource, signKeySrc KeySource) errors.Error {
	if !encryptKeySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No encryption key specified").Make()
	}

	reader, err := os.Open(inFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not open input file").Make().Cause(err)
	}

	encryptKey, err := importKeySource(encryptKeySrc, false)
	if err != nil {
		return errors.Wrap(err)
	}

	var signKey *openpgp.Entity
	if signKeySrc.HasValue() {
		key, err := importKeySource(signKeySrc, true)
		if err != nil {
			return err.Expand("Could not import sign key")
		}
		signKey = key[0]
	}

	writer, err := os.Create(outFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not create output file").Make().Cause(err)
	}
	defer writer.Close()

	pgpWriter, err := openpgp.Encrypt(writer, encryptKey, signKey, &openpgp.FileHints{}, nil)
	if err != nil {
		return ErrGPG.Msg("Failed to encrypt file").Make().Cause(err)
	}
	defer pgpWriter.Close()

	gzipWriter, err := gzip.NewWriterLevel(pgpWriter, 9)
	if err != nil {
		return ErrTechnicalProblem.Msg("Unable to open gzip writer").Make().Cause(err)
	}
	defer gzipWriter.Close()

	if _, err := io.Copy(gzipWriter, reader); err != nil {
		return ErrTechnicalProblem.Msg("Failed to write encrypted and gzipped file").Make().Cause(err)
	}

	return nil
}

// ComputeDetachedSignature creates a detached signature of inFile and writes it to outFile using the given GPG key.
func ComputeDetachedSignature(inFile, outFile string, keySrc KeySource) errors.Error {
	if !keySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No signing key specified").Make()
	}

	reader, err := os.Open(inFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not open input file").Make().Cause(err)
	}

	key, err := importKeySource(keySrc, true)
	if err != nil {
		return errors.Wrap(err)
	}

	writer, err := os.Create(outFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not create output file").Make().Cause(err)
	}
	defer writer.Close()

	if err := openpgp.DetachSign(writer, key[0], reader, nil); err != nil {
		return ErrGPG.Msg("Failed to generate detached signature").Make().Cause(err)
	}

	return nil
}

func importKeySource(src KeySource, privateKey bool) (openpgp.EntityList, errors.Error) {
	var key openpgp.EntityList
	var err errors.Error
	if src.IsFileSource() {
		if AcceptFileKeySources {
			key, err = importKeyFile(src.File, privateKey)
		} else {
			return nil, ErrKeySourceNotAccepted.Args(src.String()).Make()
		}
	} else if src.IsNamedSource() {
		if AcceptNamedKeySources {
			key, err = importNamedKey(src.Owner, privateKey, src.Passphrase)
		} else {
			return nil, ErrKeySourceNotAccepted.Args(src.String()).Make()
		}
	} else {
		return nil, ErrNoKeySpecified.Make()
	}

	if err != nil {
		return nil, err
	}

	if len(src.Passphrase) > 0 {
		for i := range key {
			if err := decryptKey(key[i], src.Passphrase); err != nil {
				return nil, err
			}
		}
	}

	return key, nil
}

func importKeyFile(file string, privateKey bool) (openpgp.EntityList, errors.Error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, ErrTechnicalProblem.Msg("Unable to read key file").Make().Cause(err)
	}

	return importKey(data)
}

func importNamedKey(owner string, privateKey bool, passphrase string) (openpgp.EntityList, errors.Error) {
	//TODO allow custom named key importers
	var cmd *exec.Cmd
	if len(passphrase) > 0 {
		cmd = exec.Command(GPGCommand, "--pinentry-mode=loopback", "--passphrase", passphrase, "--armor", iif(privateKey, "--export-secret-keys", "--export"), owner)
	} else {
		cmd = exec.Command(GPGCommand, "--armor", iif(privateKey, "--export-secret-keys", "--export"), owner)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, ErrTechnicalProblem.Msg("Could not execute gpg command").Make().Cause(err)
	}
	return importKey(out)
}

func iif(cond bool, then, otherwise string) string {
	if cond {
		return then
	}
	return otherwise
}

func importKey(data []byte) (openpgp.EntityList, errors.Error) {
	reader := bytes.NewBuffer(data)
	var key openpgp.EntityList
	var err error
	if len(data) >= 3 && data[0] == 45 && data[1] == 45 && data[2] == 45 {
		key, err = openpgp.ReadArmoredKeyRing(reader)
	} else {
		key, err = openpgp.ReadKeyRing(reader)
	}

	if err != nil {
		return nil, ErrImportKeyFailed.Make().Cause(err)
	}
	return key, nil
}

func decryptKey(entity *openpgp.Entity, passphrase string) errors.Error {
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
			return ErrDecryptKeyFailed.Make().Cause(err)
		}
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			if err := subkey.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return ErrDecryptKeyFailed.Msg("Unable to decrypt a sub key").Make().Cause(err)
			}
		}
	}

	return nil
}