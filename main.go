package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"unsafe"

	"github.com/cosmos/go-bip39"
	"github.com/tmthrgd/go-memset"
)

var (
	argHdPath   string
	argCurve    string
	argMnemonic string
	argPassword string
)

const defaultMnemonicBitSize = 256

func init() {
	flag.StringVar(&argHdPath, "hdpath", "", "HD derivation path.")
	flag.StringVar(&argCurve, "curve", "ed25519", "Elliptic curve to use.")
	flag.StringVar(&argMnemonic, "mnemonic", "", "Mnemonic to derive a seed from. If empty, generate a new mnemonic.")
	flag.StringVar(&argPassword, "password", "", "Password to use with BIP-44.")
	flag.Parse()
}

func main() {
	mnemonic := getMnemonic()
	defer clearString(mnemonic)
	seed := getSeed(mnemonic)
	defer memset.Memset(seed, 0)
	path := getHdPath()
	key := DeriveKey(path, argCurve, seed)
	defer memset.Memset(key.Private, 0)
	pkHash := DerivePkHash(key)
	addr := DeriveAddress(pkHash)

	fmt.Printf("mnemonic: %s\n", mnemonic)
	fmt.Printf("public key: %s\n", hex.EncodeToString(key.Public))
	fmt.Printf("private key: %s\n", hex.EncodeToString(key.Private))
	fmt.Printf("public key hash: %s\n", hex.EncodeToString(pkHash[:20]))
	fmt.Printf("address: %s\n", addr)
}

func getHdPath() []HdIndex {
	if argHdPath == "" {
		switch argCurve {
		case "ed25519":
			path, err := ParseHdPath(DefaultHdIndexEd25519)
			if err != nil {
				panic(err)
			}
			return path
		case "secp256k1":
			path, err := ParseHdPath(DefaultHdIndexSecp256k1)
			if err != nil {
				panic(err)
			}
			return path
		default:
			panic("invalid curve: " + argCurve)
		}
	}

	path, err := ParseHdPath(argHdPath)
	if err != nil {
		panic(err)
	}
	return path
}

func getMnemonic() string {
	if argMnemonic == "" {
		entropy, err := bip39.NewEntropy(defaultMnemonicBitSize)
		if err != nil {
			panic(err)
		}
		mnemonic, err := bip39.NewMnemonic(entropy)
		memset.Memset(entropy, 0)
		if err != nil {
			panic(err)
		}
		return mnemonic
	} else {
		if !bip39.IsMnemonicValid(argMnemonic) {
			panic("invalid mnemonic: " + argMnemonic)
		}
		return argMnemonic
	}
}

func getSeed(mnemonic string) []byte {
	return bip39.NewSeed(mnemonic, argPassword)
}

func clearString(s string) {
	memset.Memset(unsafe.Slice(unsafe.StringData(s), len(s)), 0)
}
