package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ava-labs/avalanchego/utils/formatting"
	"github.com/ava-labs/avalanchego/utils/hashing"
	"github.com/zondax/ledger-go"
)

const (
	CLA                   = 0x80
	INS_VERSION           = 0x00
	INS_PROMPT_PUBLIC_KEY = 0x02
	INS_SIGN_HASH         = 0x04
	HRP                   = "fuji"
)

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
	fmt.Println("address:", addr)

	// TODO: Get Extended Public Key to get all UTXOs

	// Sign Hash
	suffixes := [][]uint32{{0, 1}, {0, 3}}
	data = []byte{byte(len(suffixes))}
	rawHash := hashing.ComputeHash256([]byte{0x1, 0x2, 0x3, 0x4})
	data = append(data, rawHash...)
	pathBytes, err = bip32bytes([]uint32{44, 9000, 0}, 3)
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
	fmt.Printf("signed hash: %x\n", rawHash)

	// Get Signatures
	sigs := collectSignaturesFromSuffixes(device, []uint32{44, 9000, 0}, suffixes)
	for i, sig := range sigs {
		fmt.Printf("sigs (%v): %x\n", suffixes[i], sig)
	}

	// TODO: Sign Transaction
	// PVM: https://github.com/ava-labs/avalanchego/blob/f0a3bbb7d745be99d4970fb3b8fba3c7da87b891/vms/platformvm/tx.go#L100-L129
}
