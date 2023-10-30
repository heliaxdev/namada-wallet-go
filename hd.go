package main

import (
	"fmt"
	"strconv"
	"strings"
)

type HdIndex = uint32

const (
	DefaultHdIndexEd25519   = "m/44'/877'/0'/0'/0'"
	DefaultHdIndexSecp256k1 = "m/44'/60'/0'/0/0"
)

func ParseHdPath(path string) ([]HdIndex, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		return nil, fmt.Errorf("hd path must have at least one part")
	}
	if parts[0] != "m" {
		return nil, fmt.Errorf("hd path must start with `m`")
	}
	var indexes []HdIndex
	for i := 1; i < len(parts); i++ {
		var (
			hardened bool
			indexStr string
		)
		if strings.HasSuffix(parts[i], "'") {
			hardened = true
			indexStr = parts[i][:len(parts[i])-1]
		} else {
			indexStr = parts[i]
		}
		index, err := strconv.ParseUint(indexStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hd derivation path index: %w", err)
		}
		if hardened {
			indexes = append(indexes, hdIndexHardened(uint32(index)))
		} else {
			indexes = append(indexes, hdIndexNormal(uint32(index)))
		}
	}
	return indexes, nil
}

func hdIndexNormal(index uint32) HdIndex {
	return index
}

func hdIndexHardened(index uint32) HdIndex {
	return (1 << 31) | index
}
