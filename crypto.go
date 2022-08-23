// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	btcutil "github.com/FactomProject/btcutilecc"
)

// This file draws inspiration from:
// * https://github.com/tyler-smith/go-bip32
// * https://www.npmjs.com/package/hdkey

const (
	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var curve = btcutil.Secp256k1()

func bip32bytes(bip32Path []uint32, hardenCount int) ([]byte, error) {
	message := make([]byte, 1+len(bip32Path)*4)
	if len(bip32Path) > 10 {
		return nil, fmt.Errorf("maximum bip32 depth = 10")
	}
	message[0] = byte(len(bip32Path))
	for index, element := range bip32Path {
		pos := 1 + index*4
		value := element
		if index < hardenCount {
			value = 0x80000000 | element
		}
		binary.BigEndian.PutUint32(message[pos:], value)
	}
	return message, nil
}

func getIntermediary(key []byte, chainCode []byte, childIdx uint32) ([]byte, error) {
	// Compress extended pk
	pkx, pky := elliptic.Unmarshal(curve, key)
	ckey := elliptic.MarshalCompressed(curve, pkx, pky)

	// Pack data bytes (assumes unhardened)
	childIndexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(childIndexBytes, childIdx)
	ckey = append(ckey, childIndexBytes...)

	// Compute HMAC
	hmac := hmac.New(sha512.New, chainCode)
	if _, err := hmac.Write(ckey); err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

func NewChild(key []byte, chainCode []byte, childIdx uint32) ([]byte, error) {
	intermediary, err := getIntermediary(key, chainCode, childIdx)
	if err != nil {
		return nil, err
	}

	// Modify public key points by intermediary
	pubX, pubY := elliptic.Unmarshal(curve, key)
	tweakX, tweakY := curve.ScalarBaseMult(intermediary[:32])
	pointX, pointY := curve.Add(pubX, pubY, tweakX, tweakY)

	// Ensure public key is valid
	if pointX.Sign() == 0 || pointY.Sign() == 0 {
		return nil, errors.New("invalid public key")
	}

	// Compress public key
	return elliptic.MarshalCompressed(curve, pointX, pointY), nil
}
