// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ava-labs/avalanchego/utils/formatting"
	ledger_go "github.com/zondax/ledger-go"
)

const (
	CLA                = 0x80
	INSVersion         = 0x00
	INSPromptPublicKey = 0x02
	INSSignHash        = 0x04
)

var pathPrefix = []uint32{44, 9000, 0}

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

func (l *Ledger) collectSignaturesFromSuffixes(suffixes [][]uint32) ([][]byte, error) {
	results := make([][]byte, len(suffixes))
	for i := 0; i < len(suffixes); i++ {
		suffix := suffixes[i]
		p1 := 0x01
		if i == len(suffixes)-1 {
			p1 = 0x81
		}
		fmt.Println("signing:", append(pathPrefix, suffix...))
		data, err := bip32bytes(suffix, 0)
		if err != nil {
			return nil, err
		}
		msgSig := []byte{
			CLA,
			INSSignHash,
			byte(p1),
			0x0,
		}
		msgSig = append(msgSig, byte(len(data)))
		msgSig = append(msgSig, data...)
		sig, err := l.device.Exchange(msgSig)
		if err != nil {
			return nil, err
		}
		results[i] = sig[:len(sig)-2]
	}
	return results, nil
}

type Ledger struct {
	device ledger_go.LedgerDevice
}

func Connect() (*Ledger, error) {
	admin := ledger_go.NewLedgerAdmin()
	device, err := admin.Connect(0)
	if err != nil {
		return nil, err
	}
	return &Ledger{device}, nil
}

func (l *Ledger) Version() (version string, commit string, name string, err error) {
	msgVersion := []byte{
		CLA,
		INSVersion,
		0x0,
		0x0,
		0x0,
	}
	rawVersion, err := l.device.Exchange(msgVersion)
	if err != nil {
		return
	}

	version = fmt.Sprintf("%d.%d.%d", rawVersion[0], rawVersion[1], rawVersion[2])
	rem := bytes.Split(rawVersion[3:], []byte{0x0})
	commit = fmt.Sprintf("%x", rem[0])
	name = string(rem[1])
	return
}

// m/44'/9000'/0'/0/n where n is the address index
// m/44'/9000'/0'/1/n where n is the address index (X-Chain "change" addresses)
func (l *Ledger) Address(hrp string, accountIndex uint32, changeIndex uint32) (string, error) {
	msgPK := []byte{
		CLA,
		INSPromptPublicKey,
		0x4,
		0x0,
	}
	pathBytes, err := bip32bytes(append(pathPrefix, changeIndex, accountIndex), 3)
	if err != nil {
		return "", err
	}
	data := append([]byte(hrp), pathBytes...)
	msgPK = append(msgPK, byte(len(data)))
	msgPK = append(msgPK, data...)
	rawAddress, err := l.device.Exchange(msgPK)
	if err != nil {
		return "", err
	}

	return formatting.FormatBech32(hrp, rawAddress)
}

func (l *Ledger) SignHash(hash []byte, suffixes [][]uint32) ([][]byte, error) {
	msgHash := []byte{
		CLA,
		INSSignHash,
		0x0,
		0x0,
	}
	pathBytes, err := bip32bytes(pathPrefix, 3)
	if err != nil {
		return nil, err
	}
	data := []byte{byte(len(suffixes))}
	data = append(data, hash...)
	data = append(data, pathBytes...)
	msgHash = append(msgHash, byte(len(data)))
	msgHash = append(msgHash, data...)
	resp, err := l.device.Exchange(msgHash)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(resp, hash) {
		return nil, fmt.Errorf("returned hash %x does not match requested %x", resp, hash)
	}

	return l.collectSignaturesFromSuffixes(suffixes)
}
