package main

import (
	"crypto/sha256"

	"github.com/pactus-project/pactus/util/bech32m"
)

func encodePubKeyBytes(key *Key) []byte {
	var rawKey []byte

	switch key.Kind {
	case KindEd25519:
		rawKey = make([]byte, 1+32)
		copy(rawKey[1:], key.Public)
	case KindSecp256k1:
		rawKey = make([]byte, 1+33)
		rawKey[0] = 1
		copy(rawKey[1:], key.Public)
	}

	return rawKey
}

func DerivePkHash(key *Key) [32]byte {
	return sha256.Sum256(encodePubKeyBytes(key))
}

func DeriveAddress(digest [32]byte) string {
	var data [21]byte
	copy(data[1:], digest[:20])

	converted, err := bech32m.ConvertBits(data[:], 8, 5, true)
	if err != nil {
		panic(err)
	}

	addr, err := bech32m.Encode("tnam", converted)
	if err != nil {
		panic(err)
	}

	return addr
}

func DerivePublicKey(key *Key) string {
	converted, err := bech32m.ConvertBits(encodePubKeyBytes(key)[:], 8, 5, true)
	if err != nil {
		panic(err)
	}

	addr, err := bech32m.Encode("tpknam", converted)
	if err != nil {
		panic(err)
	}

	return addr
}
