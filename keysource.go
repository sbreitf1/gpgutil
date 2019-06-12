package gpgutil

// KeySource describes a file or named source for protected and unprotected PGP keys.
type KeySource struct {
	File       string `json:"file"`
	Owner      string `json:"owner"`
	Passphrase string `json:"passphrase"`
}

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
