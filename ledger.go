// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"bytes"
	"fmt"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/formatting"
	"github.com/ava-labs/avalanchego/utils/hashing"
	ledger_go "github.com/zondax/ledger-go"
)

const (
	CLA                   = 0x80
	INSVersion            = 0x00
	INSPromptPublicKey    = 0x02
	INSPromptExtPublicKey = 0x03
	INSSignHash           = 0x04
)

var pathPrefix = []uint32{44, 9000, 0}

func (l *Ledger) collectSignaturesFromSuffixes(suffixes [][]uint32) ([][]byte, error) {
	results := make([][]byte, len(suffixes))
	for i := 0; i < len(suffixes); i++ {
		suffix := suffixes[i]
		p1 := 0x01
		if i == len(suffixes)-1 {
			p1 = 0x81
		}
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
		results[i] = sig
		fmt.Printf("%v signed: %X\n", append(pathPrefix, suffix...), results[i])
	}
	return results, nil
}

// Ledger is a wrapper around the low-level Ledger Device interface that
// provides Avalanche-specific access.
type Ledger struct {
	device ledger_go.LedgerDevice
}

// Connect attempts to connect to a Ledger on the device over HID.
func Connect() (*Ledger, error) {
	admin := ledger_go.NewLedgerAdmin()
	device, err := admin.Connect(0)
	if err != nil {
		return nil, err
	}
	return &Ledger{device}, nil
}

// Disconnect attempts to disconnect from a previously connected Ledger.
func (l *Ledger) Disconnect() error {
	return l.device.Close()
}

// Version returns information about the Avalanche Ledger app. If a different
// app is open, this will return an error.
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

// Address is a succinct representation of an Avalanche Address
type Address struct {
	Addr      string
	ShortAddr ids.ShortID
	Index     uint32
}

// Address returns an Avalanche-formatted address with the provided [hrp].
//
// On the P/X-Chain, accounts are derived on the path m/44'/9000'/0'/0/n
// (where n is the address index).
func (l *Ledger) Address(hrp string, addressIndex uint32) (*Address, error) {
	msgPK := []byte{
		CLA,
		INSPromptPublicKey,
		0x4,
		0x0,
	}
	pathBytes, err := bip32bytes(append(pathPrefix, 0, addressIndex), 3)
	if err != nil {
		return nil, err
	}
	data := append([]byte(hrp), pathBytes...)
	msgPK = append(msgPK, byte(len(data)))
	msgPK = append(msgPK, data...)
	rawAddress, err := l.device.Exchange(msgPK)
	if err != nil {
		return nil, err
	}

	addr, err := formatting.FormatBech32(hrp, rawAddress)
	if err != nil {
		return nil, err
	}
	shortAddr, err := ids.ToShortID(rawAddress)
	if err != nil {
		return nil, err
	}
	return &Address{
		Addr:      addr,
		ShortAddr: shortAddr,
		Index:     addressIndex,
	}, nil
}

func (l *Ledger) getExtendedPublicKey() ([]byte, []byte, error) {
	msgEPK := []byte{
		CLA,
		INSPromptExtPublicKey,
		0x0,
		0x0,
	}
	pathBytes, err := bip32bytes(append(pathPrefix, 0), 3)
	if err != nil {
		return nil, nil, err
	}
	msgEPK = append(msgEPK, byte(len(pathBytes)))
	msgEPK = append(msgEPK, pathBytes...)
	response, err := l.device.Exchange(msgEPK)
	if err != nil {
		return nil, nil, err
	}
	pkLen := response[0]
	chainCodeOffset := 2 + pkLen
	chainCodeLength := response[1+pkLen]
	fmt.Println("total len", len(response))
	return response[1 : 1+pkLen], response[chainCodeOffset : chainCodeOffset+chainCodeLength], nil
}

// Addresses returns [addresses] Avalanche-formatted addresses with the
// provided [hrp].
//
// On the P/X-Chain, accounts are derived on the path m/44'/9000'/0'/0/n
// (where n is the address index).
func (l *Ledger) Addresses(hrp string, addresses int) ([]*Address, error) {
	pk, chainCode, err := l.getExtendedPublicKey()
	if err != nil {
		return nil, err
	}

	addrs := make([]*Address, addresses)
	for i := 0; i < addresses; i++ {
		index := uint32(i)
		k, err := NewChild(pk, chainCode, uint32(i))
		if err != nil {
			return nil, err
		}
		shortAddr, err := ids.ToShortID(hashing.PubkeyBytesToAddress(k))
		if err != nil {
			return nil, err
		}
		addr, err := formatting.FormatBech32(hrp, shortAddr[:])
		if err != nil {
			return nil, err
		}
		addrs[i] = &Address{
			Addr:      addr,
			ShortAddr: shortAddr,
			Index:     index,
		}
	}
	return addrs, nil
}

// SignHash attempts to sign the [hash] with the provided path [suffixes].
// [suffixes] are appened to the [pathPrefix] (m/44'/9000'/0').
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
	fmt.Printf("signing hash: %X\n", hash)
	resp, err := l.device.Exchange(msgHash)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(resp, hash) {
		return nil, fmt.Errorf("returned hash %x does not match requested %x", resp, hash)
	}

	return l.collectSignaturesFromSuffixes(suffixes)
}
