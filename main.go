package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ava-labs/avalanchego/utils/formatting"
	"github.com/ava-labs/avalanchego/utils/hashing"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/tyler-smith/go-bip32"
	"github.com/wemeetagain/go-hdwallet"
	"github.com/zondax/ledger-go"
	"golang.org/x/crypto/ripemd160"
)

const (
	CLA                       = 0x80
	INS_VERSION               = 0x00
	INS_PROMPT_PUBLIC_KEY     = 0x02
	INS_PROMPT_EXT_PUBLIC_KEY = 0x03
	INS_SIGN_HASH             = 0x04
	HRP                       = "fuji"
)

var curve *btcec.KoblitzCurve = btcec.S256()

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

func collectSignaturesFromSuffixes(device ledger_go.LedgerDevice, prefix []uint32, suffixes [][]uint32) [][]byte {
	results := make([][]byte, len(suffixes))
	for i := 0; i < len(suffixes); i++ {
		suffix := suffixes[i]
		p1 := 0x01
		if i == len(suffixes)-1 {
			p1 = 0x81
		}
		fmt.Println("signing:", append(prefix, suffix...))
		data, err := bip32bytes(suffix, 0)
		if err != nil {
			panic(err)
		}
		msgSig := []byte{
			CLA,
			INS_SIGN_HASH,
			byte(p1),
			0x0,
		}
		msgSig = append(msgSig, byte(len(data)))
		msgSig = append(msgSig, data...)
		sig, err := device.Exchange(msgSig)
		if err != nil {
			panic(err)
		}
		results[i] = sig[:len(sig)-2]
	}
	return results
}

func compress(x, y *big.Int) []byte {
	two := big.NewInt(2)
	rem := two.Mod(y, two).Uint64()
	rem += 2
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(rem))
	rest := x.Bytes()
	pad := 32 - len(rest)
	if pad != 0 {
		zeroes := make([]byte, pad)
		rest = append(zeroes, rest...)
	}
	return append(b[1:], rest...)
}

//2.3.4 of SEC1 - http://www.secg.org/index.php?action=secg,docs_secg
func expand(key []byte) (*big.Int, *big.Int) {
	params := curve.Params()
	exp := big.NewInt(1)
	exp.Add(params.P, exp)
	exp.Div(exp, big.NewInt(4))
	x := big.NewInt(0).SetBytes(key[1:33])
	y := big.NewInt(0).SetBytes(key[:1])
	beta := big.NewInt(0)
	beta.Exp(x, big.NewInt(3), nil)
	beta.Add(beta, big.NewInt(7))
	beta.Exp(beta, exp, params.P)
	if y.Add(beta, y).Mod(y, big.NewInt(2)).Int64() == 0 {
		y = beta
	} else {
		y = beta.Sub(params.P, beta)
	}
	return x, y
}

func addPubKeys(k1, k2 []byte) []byte {
	x1, y1 := expand(k1)
	x2, y2 := expand(k2)
	return compress(curve.Add(x1, y1, x2, y2))
}

func uint32ToByte(i uint32) []byte {
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, i)
	return a
}

func privToPub(key []byte) []byte {
	return compress(curve.ScalarBaseMult(key))
}

func hash160(data []byte) []byte {
	sha := sha256.New()
	ripe := ripemd160.New()
	sha.Write(data)
	ripe.Write(sha.Sum(nil))
	return ripe.Sum(nil)
}

func derivePK(xpub []byte, chainCode []byte, child uint32) []byte {
	mac := hmac.New(sha512.New, chainCode)
	mac.Write(append(xpub, uint32ToByte(child)...))
	I := mac.Sum(nil)
	iL := new(big.Int).SetBytes(I[:32])
	if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
		panic("Invalid Child")
	}
	return addPubKeys(privToPub(I[:32]), xpub)
}

func derivePKs(xpub []byte, chainCode []byte, start int, limit int) [][]byte {
	// https://github.com/bitcoinjs/bip32/blob/ff170dbea03fe4710c24aa550058e5775cf344d3/src/bip32.js#L119
	// derive(0/index)
	k := &bip32.Key{
		Key:       xpub,
		Depth:     4,
		ChainCode: chainCode,
	}
	k0, err := k.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	return [][]byte{k0.Key}
}

func main() {
	// Connect to Ledger
	admin := ledger_go.NewLedgerAdmin()
	device, err := admin.Connect(0)
	if err != nil {
		panic(err)
	}

	// Get version
	msgVersion := []byte{
		CLA,
		INS_VERSION,
		0x0,
		0x0,
		0x0,
	}

	// Make version request
	rawVersion, err := device.Exchange(msgVersion)
	if err != nil {
		panic(err)
	}
	fmt.Printf("version: %d.%d.%d\n", rawVersion[0], rawVersion[1], rawVersion[2])
	rem := bytes.Split(rawVersion[3:], []byte{0x0})
	fmt.Printf("commit: %x\n", rem[0])
	fmt.Printf("name: %s\n", rem[1])

	// Construct public key request
	msgPK := []byte{
		CLA,
		INS_PROMPT_PUBLIC_KEY,
		0x4,
		0x0,
	}
	data := []byte(HRP)
	pathBytes, err := bip32bytes([]uint32{44, 9000, 0, 0, 0}, 3)
	if err != nil {
		panic(err)
	}
	data = append(data, pathBytes...)
	msgPK = append(msgPK, byte(len(data)))
	msgPK = append(msgPK, data...)

	// Make public key request
	rawAddress, err := device.Exchange(msgPK)
	if err != nil {
		panic(err)
	}

	// Format public key response
	addr, err := formatting.FormatBech32(HRP, rawAddress)
	if err != nil {
		panic(err)
	}
	fmt.Printf("pk: %x address: %s\n", rawAddress, addr)

	// Get Extended Public Key to get all UTXOs
	msgEPK := []byte{
		CLA,
		INS_PROMPT_EXT_PUBLIC_KEY,
		0x0,
		0x0,
	}
	pathBytes, err = bip32bytes([]uint32{44, 9000, 0, 0}, 3)
	if err != nil {
		panic(err)
	}
	msgEPK = append(msgEPK, byte(len(pathBytes)))
	msgEPK = append(msgEPK, pathBytes...)
	epk, err := device.Exchange(msgEPK)
	if err != nil {
		panic(err)
	}
	pkLen := epk[0]
	chainCodeOffset := 2 + pkLen
	chainCodeLength := epk[1+pkLen]
	xpub := epk[1 : 1+pkLen]
	chainCode := epk[chainCodeOffset : chainCodeOffset+chainCodeLength]
	fmt.Printf("extended public key (xpub): %x\n", xpub)
	fmt.Printf("chain code: %x\n", chainCode)

	pks := derivePKs(xpub, chainCode, 0, 10)
	for i, pk := range pks {
		addr, err := formatting.FormatBech32(HRP, pk)
		if err != nil {
			panic(err)
		}
		fmt.Printf("bip-32 pk: %x address (%d): %s\n", pk, i, addr)
	}

	pk2 := derivePK(xpub, chainCode, 0)
	addr2, err := formatting.FormatBech32(HRP, pk2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("homemade pk: %x address (%d): %s\n", pk2, 0, addr2)

	fmt.Println("xpub len", len(xpub))
	fmt.Println("xpub:", string(xpub))
	pkss, err := hdwallet.StringChild(base58.Encode(xpub), 0)
	if err != nil {
		panic(err)
	}
	pk3 := base58.Decode(pkss)
	addr3, err := formatting.FormatBech32(HRP, pk3)
	if err != nil {
		panic(err)
	}
	fmt.Printf("3 pk: %x address (%d): %s\n", pk3, 0, addr3)

	// Sign Hash
	prefix := []uint32{44, 9000, 0}
	suffixes := [][]uint32{{0, 1}, {0, 3}}
	data = []byte{byte(len(suffixes))}
	rawHash := hashing.ComputeHash256([]byte{0x1, 0x2, 0x3, 0x4})
	data = append(data, rawHash...)
	pathBytes, err = bip32bytes(prefix, 3)
	if err != nil {
		panic(err)
	}
	data = append(data, pathBytes...)
	msgHash := []byte{
		CLA,
		INS_SIGN_HASH,
		0x0,
		0x0,
	}
	msgHash = append(msgHash, byte(len(data)))
	msgHash = append(msgHash, data...)
	responseHash, err := device.Exchange(msgHash)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(responseHash, rawHash) {
		panic("signed hash changed")
	}
	fmt.Printf("message hash: %x\n", rawHash)

	// Get Signatures
	sigs := collectSignaturesFromSuffixes(device, prefix, suffixes)
	for i, sig := range sigs {
		fmt.Printf("sigs (%v): %x\n", append(prefix, suffixes[i]...), sig)
	}

	// TODO: Sign Transaction
	// PVM: https://github.com/ava-labs/avalanchego/blob/f0a3bbb7d745be99d4970fb3b8fba3c7da87b891/vms/platformvm/tx.go#L100-L129
}
