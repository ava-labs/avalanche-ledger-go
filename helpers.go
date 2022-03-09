package ledger

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
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

func getIntermediary(key []byte, chainCode []byte, childIdx uint32) ([]byte, error) {
	childIndexBytes := uint32Bytes(childIdx)
	data := append(key, childIndexBytes...)

	hmac := hmac.New(sha512.New, chainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

func expandPublicKey(key []byte) (*big.Int, *big.Int) {
	Y := big.NewInt(0)
	X := big.NewInt(0)
	X.SetBytes(key[1:])

	// y^2 = x^3 + ax^2 + b
	// a = 0
	// => y^2 = x^3 + b
	ySquared := big.NewInt(0)
	ySquared.Exp(X, big.NewInt(3), nil)
	ySquared.Add(ySquared, curveParams.B)

	Y.ModSqrt(ySquared, curveParams.P)

	Ymod2 := big.NewInt(0)
	Ymod2.Mod(Y, big.NewInt(2))

	signY := uint64(key[0]) - 2
	if signY != Ymod2.Uint64() {
		Y.Sub(curveParams.P, Y)
	}

	return X, Y
}

func validateChildPublicKey(key []byte) error {
	x, y := expandPublicKey(key)

	if x.Sign() == 0 || y.Sign() == 0 {
		return errors.New("Invalid public key")
	}

	return nil
}

// Inspired by: https://github.com/tyler-smith/go-bip32
func NewChildKey(key []byte, chainCode []byte, childIdx uint32) ([]byte, error) {
	intermediary, err := getIntermediary(key, chainCode, childIdx)
	if err != nil {
		return nil, err
	}
	pubX, pubY := elliptic.Unmarshal(curve, key)
	tweakX, tweakY := curve.ScalarBaseMult(intermediary[:32])
	pointX, pointY := curve.Add(pubX, pubY, tweakX, tweakY)
	childKey := elliptic.MarshalCompressed(curve, pointX, pointY)
	return childKey, validateChildPublicKey(childKey)
}
