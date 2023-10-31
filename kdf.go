package main

import (
	"github.com/anyproto/go-slip10"
	"github.com/tmthrgd/go-memset"
	"github.com/tyler-smith/go-bip32"
)

const (
	KindEd25519 = iota
	KindSecp256k1
)

type Key struct {
	Kind    uint8
	Public  []byte
	Private []byte
}

func DeriveKey(path []HdIndex, curve string, seed []byte) *Key {
	switch curve {
	case "ed25519":
		return deriveKeyEd25519(path, seed)
	case "secp256k1":
		return deriveKeySecp256k1(path, seed)
	default:
		panic("invalid curve: " + curve)
	}
}

func deriveKeyEd25519(path []HdIndex, seed []byte) *Key {
	node, err := slip10.NewMasterNode(seed)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(path); i++ {
		var newNode slip10.Node
		newNode, err = node.Derive(path[i])
		memset.Memset(node.RawSeed(), 0)
		if err != nil {
			panic(err)
		}
		node = newNode
	}
	pub, sec := node.Keypair()
	return &Key{
		Kind:    KindEd25519,
		Public:  []byte(pub),
		Private: sec.Seed(),
	}
}

func deriveKeySecp256k1(path []HdIndex, seed []byte) *Key {
	node, err := bip32.NewMasterKey(seed)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(path); i++ {
		var newNode *bip32.Key
		newNode, err = node.NewChildKey(path[i])
		memset.Memset(node.Key, 0)
		if err != nil {
			panic(err)
		}
		node = newNode
	}
	return &Key{
		Kind:    KindSecp256k1,
		Public:  node.PublicKey().Key,
		Private: node.Key[1:],
	}
}
