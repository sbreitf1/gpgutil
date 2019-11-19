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
	pgperr "golang.org/x/crypto/openpgp/errors"
)

var (
	// ErrTechnicalProblem occurs on all errors not related to cryptography.
	ErrTechnicalProblem = errors.New("Technical error")
	// ErrNoKeySpecified occurs when a mandatory key is not specified.
	ErrNoKeySpecified = errors.New("No key specified")
	// ErrNoPrivateKey occurs when a public key is supplied, but a private key is expected.
	ErrNoPrivateKey = errors.New("Require private key")
	// ErrWrongKey occurs when a wrong key is used for decrypting or signature checking.
	ErrWrongKey = errors.New("Wrong key")
	// ErrKeySourceNotAccepted occurs on importing a disabled key source (See gpgutil.AcceptFileKeySources and gpgutil.AcceptNamedKeySources)
	ErrKeySourceNotAccepted = errors.New("Key source %q not accepted")
	// ErrImportKeyFailed occurs when a specified key could not be imported.
	ErrImportKeyFailed = errors.New("Failed to import key")
	// ErrDecryptKeyFailed occurs when a specified key was imported but could not be decrypted.
	ErrDecryptKeyFailed = errors.New("Failed to decrypt key")
	// ErrWrongSignatureVerificationKey occurs when the key for signature verification does not match the signer.
	ErrWrongSignatureVerificationKey = errors.New("Wrong key for signature verification")
	// ErrWrongSignature occurs when a signature does not verify the given message.
	ErrWrongSignature = errors.New("Wrong signature")
	// ErrMissingSignature occurs when a signature was expected but does not exist.
	ErrMissingSignature = errors.New("Missing signature")
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

// Options define additional parameters
type Options struct {
	GZIP         bool
	SignatureKey KeySource
}

func init() {
	GPGCommand = "gpg"
	AcceptFileKeySources = true
	AcceptNamedKeySources = true
}

// EncryptAndSignFile encrypts and signs the given file using the given GPG keys and applies GZIP compression.
//
// DEPRECATED: Use EncryptFile(... &Options{SignatureKey: SignKeySource}) instead.
func EncryptAndSignFile(inFile, outFile string, encryptKeySrc, signKeySrc KeySource, options *Options) errors.Error {
	if !signKeySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No signing key specified").Make()
	}
	if options == nil {
		options = &Options{SignatureKey: signKeySrc}
	} else {
		if signKeySrc.HasValue() {
			options.SignatureKey = signKeySrc
		}
	}
	return EncryptFile(inFile, outFile, encryptKeySrc, options)
}

// EncryptFile encrypts the given file using the given GPG keys.
func EncryptFile(inFile, outFile string, encryptKeySrc KeySource, options *Options) errors.Error {
	reader, err := os.Open(inFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not open input file").Make().Cause(err)
	}
	defer reader.Close()

	writer, err := os.Create(outFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not create output file").Make().Cause(err)
	}
	defer writer.Close()

	return encrypt(reader, writer, encryptKeySrc, options)
}

// EncryptByteSliceToFile encrypts a byte slice and writes the data to a file.
func EncryptByteSliceToFile(data []byte, outFile string, keySrc KeySource, options *Options) errors.Error {
	reader := bytes.NewReader(data)

	writer, err := os.Create(outFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not create output file").Make().Cause(err)
	}
	defer writer.Close()

	return encrypt(reader, writer, keySrc, options)
}

func encrypt(reader io.Reader, writer io.Writer, encryptKeySrc KeySource, options *Options) errors.Error {
	if !encryptKeySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No encryption key specified").Make()
	}

	encryptKey, importErr := importKeySource(encryptKeySrc, false)
	if importErr != nil {
		return importErr.Expand("Could not import encryption key")
	}

	var signKey *openpgp.Entity
	if options != nil && options.SignatureKey.HasValue() {
		key, err := importKeySource(options.SignatureKey, true)
		if err != nil {
			return err.Expand("Could not import signing key")
		}
		//TODO assert len=1
		signKey = key[0]
	}

	pgpWriter, err := openpgp.Encrypt(writer, encryptKey, signKey, &openpgp.FileHints{}, nil)
	if err != nil {
		return ErrGPG.Msg("Failed to encrypt file").Make().Cause(err)
	}
	defer pgpWriter.Close()
	dstWriter := pgpWriter

	if options != nil && options.GZIP {
		gzipWriter, err := gzip.NewWriterLevel(dstWriter, 9)
		if err != nil {
			return ErrTechnicalProblem.Msg("Unable to open gzip writer").Make().Cause(err)
		}
		defer gzipWriter.Close()
		dstWriter = gzipWriter
	}

	if _, err := io.Copy(dstWriter, reader); err != nil {
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

	key, importErr := importKeySource(keySrc, true)
	if importErr != nil {
		return importErr.Expand("Could not import signing key")
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

// DecryptFile decrypts a gpg file.
func DecryptFile(inFile, outFile string, keySrc KeySource, options *Options) errors.Error {
	reader, err := os.Open(inFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not open input file").Make().Cause(err)
	}
	defer reader.Close()

	writer, err := os.Create(outFile)
	if err != nil {
		return ErrTechnicalProblem.Msg("Could not create output file").Make().Cause(err)
	}
	defer writer.Close()

	if err := decrypt(reader, writer, keySrc, options); err != nil {
		return err
	}

	return nil
}

// DecryptFileAndCheckSignature decrypts a gpg file and checks the signature.
//
// DEPRECATED: Use DecryptFile(... &Options{SignatureKey: SignKeySource}) instead.
func DecryptFileAndCheckSignature(inFile, outFile string, decryptKeySrc, signKeySrc KeySource, options *Options) errors.Error {
	if !signKeySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No signature key specified").Make()
	}
	if options == nil {
		options = &Options{SignatureKey: signKeySrc}
	} else {
		if signKeySrc.HasValue() {
			options.SignatureKey = signKeySrc
		}
	}
	return DecryptFile(inFile, outFile, decryptKeySrc, options)
}

// DecryptFileToByteSlice decrypts a gpg file and returns the data as byte slice.
func DecryptFileToByteSlice(inFile string, keySrc KeySource, options *Options) ([]byte, errors.Error) {
	reader, err := os.Open(inFile)
	if err != nil {
		return nil, ErrTechnicalProblem.Msg("Could not open input file").Make().Cause(err)
	}
	defer reader.Close()

	writer := bytes.NewBuffer(nil)

	if err := decrypt(reader, writer, keySrc, options); err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}

func decrypt(reader io.Reader, writer io.Writer, decryptKeySrc KeySource, options *Options) errors.Error {
	if !decryptKeySrc.HasValue() {
		return ErrNoKeySpecified.Msg("No decryption key specified").Make()
	}

	decryptKey, importErr := importKeySource(decryptKeySrc, true)
	if importErr != nil {
		return importErr.Expand("Could not import decryption key")
	}

	keyRing := decryptKey
	var signKey *openpgp.Entity
	if options != nil && options.SignatureKey.HasValue() {
		key, err := importKeySource(options.SignatureKey, false)
		if err != nil {
			return err.Expand("Could not import signature key")
		}
		//TODO assert len=1
		signKey = key[0]
		keyRing = append(keyRing, signKey)
	}

	msg, err := openpgp.ReadMessage(reader, keyRing, nil, nil)
	if err != nil {
		if err == pgperr.ErrKeyIncorrect {
			return ErrWrongKey.Make()
		}
		return ErrGPG.Msg("Failed to read encrypted message").Make().Cause(err)
	}

	if signKey != nil {
		if !msg.IsSigned {
			return ErrMissingSignature.Make()
		}
		if msg.SignedBy == nil || msg.SignedBy.PublicKey.Fingerprint != signKey.PrimaryKey.Fingerprint {
			return ErrWrongSignatureVerificationKey.Make()
		}
	}

	srcReader := msg.UnverifiedBody

	if options != nil && options.GZIP {
		srcReader, err = gzip.NewReader(srcReader)
		if err != nil {
			return ErrTechnicalProblem.Msg("Unable to open gzip reader").Make().Cause(err)
		}
	}

	if signKey != nil {
		if msg.SignatureError != nil {
			return ErrWrongSignature.Make().Cause(msg.SignatureError)
		}
	}

	if _, err := io.Copy(writer, srcReader); err != nil {
		return ErrTechnicalProblem.Msg("Failed to decrypt and unzip file").Make().Cause(err)
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

	if privateKey {
		privateKeyCount := 0
		for i := range key {
			if key[i].PrivateKey != nil {
				privateKeyCount++
			}
		}
		if privateKeyCount == 0 {
			return nil, ErrNoPrivateKey.Make()
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
