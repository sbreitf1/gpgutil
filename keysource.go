package gpgutil

// KeySource describes a file or named source for protected and unprotected PGP keys.
type KeySource struct {
	File       string `json:"file"`
	Owner      string `json:"owner"`
	Passphrase string `json:"passphrase"`
}

//TODO generate keys and save in abstracted memory representation

// HasValue returns wether the key source contains a key.
func (obj KeySource) HasValue() bool {
	return len(obj.File) > 0 || len(obj.Owner) > 0
}

// IsFileSource returns true, when the key source is a file.
func (obj KeySource) IsFileSource() bool {
	return len(obj.File) > 0
}

// IsNamedSource returns true, when the key source denotes a key in local gpg store.
func (obj KeySource) IsNamedSource() bool {
	return !obj.IsFileSource() && len(obj.Owner) > 0
}

func (obj KeySource) String() string {
	if obj.IsFileSource() {
		return obj.File
	} else if obj.IsNamedSource() {
		return obj.Owner
	}
	return "{EMPTY}"
}

// MakeEmptyKeySource returns a key source that does not describe a key. Can be used for optional keys.
func MakeEmptyKeySource() KeySource {
	return KeySource{}
}

// MakeFileKeySource returns a file key source with passphrase. Leave empty for unencrypted keys.
func MakeFileKeySource(file, password string) KeySource {
	return KeySource{File: file, Passphrase: password}
}

// MakeNamedKeySource returns a named key source with passphrase. Leave empty for unencrypted keys.
func MakeNamedKeySource(owner, password string) KeySource {
	return KeySource{Owner: owner, Passphrase: password}
}

/*
func GenerateKey(name, comment, email, pubKeyFile, privKeyFile string) (KeySource, errors.Error) {
	key, err := openpgp.NewEntity(name, comment, email, nil)
	if err != nil {
		return MakeEmptyKeySource(), ErrGPG.Msg("Could not create new key").Make().Cause(err)
	}

	fPriv, err := os.Create(privKeyFile)
	if err != nil {
		return MakeEmptyKeySource(), ErrTechnicalProblem.Msg("Could not create output file for private key").Make().Cause(err)
	}
	wPriv, err := armor.Encode(fPriv, openpgp.PrivateKeyType, nil)
	if err != nil {
		return MakeEmptyKeySource(), ErrGPG.Msg("Could not prepare armored writer for private key").Make().Cause(err)
	}
	if err := key.SerializePrivate(wPriv, nil); err != nil {
		return MakeEmptyKeySource(), ErrGPG.Msg("Could not write armored private key").Make().Cause(err)
	}

	fPub, err := os.Create(pubKeyFile)
	if err != nil {
		return MakeEmptyKeySource(), ErrTechnicalProblem.Msg("Could not create output file for public key").Make().Cause(err)
	}
	wPub, err := armor.Encode(fPub, openpgp.PublicKeyType, nil)
	if err != nil {
		return MakeEmptyKeySource(), ErrGPG.Msg("Could not prepare armored writer for public key").Make().Cause(err)
	}
	if err := key.Serialize(wPub); err != nil {
		return MakeEmptyKeySource(), ErrGPG.Msg("Could not write armored public key").Make().Cause(err)
	}

	return MakeEmptyKeySource()
}
*/
