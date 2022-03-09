package ledger

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	btcutil "github.com/FactomProject/btcutilecc"
)

const (
	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	curve       = btcutil.Secp256k1()
	curveParams = curve.Params()
)

//
// Crypto
//
func compressPublicKey(x *big.Int, y *big.Int) []byte {
	var key bytes.Buffer

	// Write header; 0x2 for even y value; 0x3 for odd
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))

	// Write X coord; Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
	xBytes := x.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)

	return key.Bytes()
}

//
// Numerical
//
func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func getIntermediary(ckey []byte, chainCode []byte, childIdx uint32) ([]byte, error) {
	childIndexBytes := uint32Bytes(childIdx)
	data := append(ckey, childIndexBytes...)
	fmt.Printf("data buff: %x\n", data)

	hmac := hmac.New(sha512.New, chainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

// Inspired by: https://github.com/tyler-smith/go-bip32
func NewChildKey(key []byte, chainCode []byte, childIdx uint32) ([]byte, error) {
	pubX, pubY := elliptic.Unmarshal(curve, key)
	ckey := elliptic.MarshalCompressed(curve, pubX, pubY)
	intermediary, err := getIntermediary(ckey, chainCode, childIdx)
	if err != nil {
		return nil, err
	}
	fmt.Printf("intermediary: %x child: %d starting ck: %x\n", intermediary[:32], childIdx, ckey)
	tweakX, tweakY := curve.ScalarBaseMult(intermediary[:32])
	pointX, pointY := curve.Add(pubX, pubY, tweakX, tweakY)
	if pointX.Sign() == 0 || pointY.Sign() == 0 {
		return nil, errors.New("Invalid public key")
	}
	return elliptic.Marshal(curve, pointX, pointY), nil
}
