package tzwallet

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"
)

//const DERIVATION_PATH = "m/44'/1729'/0'/0/%d"

var (
	// see: https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml#L343
	tz1prefix  = []byte{6, 161, 159}
	edskprefix = []byte{43, 246, 78, 7}
	edpkprefix = []byte{13, 15, 37, 217}
)

type Wallet struct {
	address    string
	mnemonic   string
	password   string
	seed       []byte
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	pk         string
	sk         string
}

func (w *Wallet) Address() string {
	return w.address
}

func (w *Wallet) String() string {
	return fmt.Sprintf(`Mnemonic:   %s
Hash:       %s
Public Key: %s
Secret Key: unencrypted:%s`, w.mnemonic, w.address, w.pk, w.sk)
}

func encode(b []byte) string {
	checksum := sha256.Sum256(b)
	checksum = sha256.Sum256(checksum[:])
	b = append(b, checksum[:4]...)
	count := 0
	for count = range b {
		if b[count] != 0 {
			break
		}
	}
	return strings.Repeat("1", count) + base58.Encode(b)
}

func KeysFromSeed(seed []byte) (address string, pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)
	var h hash.Hash
	h, err = blake2b.New(20, []byte{})
	if err == nil {
		if _, err = h.Write(pub); err == nil {
			address = encode(append(tz1prefix, h.Sum(nil)...))
		}
	}
	return
}

func PublicKeyFrom(k ed25519.PublicKey) string {
	return encode(append(edpkprefix, k...))
}

func SecretKeyFrom(k ed25519.PrivateKey) string {
	return encode(append(edskprefix, k...))
}

func NewSeed(mnemonic, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 32, sha512.New)
}

// NewMnemonic generates a new HD Wallet mnemonic phrase
func NewMnemonic() (string, error) {
	var mnemonic string
	entropy, err := bip39.NewEntropy(256)
	if err == nil {
		mnemonic, err = bip39.NewMnemonic(entropy)
	}
	return mnemonic, err
}

func NewFromMnemonicAndPassword(mnemonic string, password string) (*Wallet, error) {
	seed := NewSeed(mnemonic, password)
	address, pub, priv, err := KeysFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return &Wallet{
		address:    address,
		mnemonic:   mnemonic,
		password:   password,
		seed:       seed,
		publicKey:  pub,
		privateKey: priv,
		pk:         PublicKeyFrom(pub),
		sk:         SecretKeyFrom(priv),
	}, nil
}

func NewFromPassword(password string) (*Wallet, error) {
	mnemonic, err := NewMnemonic()
	if err != nil {
		return nil, err
	}
	return NewFromMnemonicAndPassword(mnemonic, password)
}

func New() (*Wallet, error) {
	return NewFromPassword("")
}
