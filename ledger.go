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
	INSSignTransaction    = 0x05
	MaxApduSize           = 230
)

// Internal wrapper for Exchange function
func (l *Ledger) SendToLedger(cla byte, ins byte, p1 byte, p2 byte, buffer []byte) ([]byte, error) {
	msgSend := append([]byte{
		cla,
		ins,
		p1,
		p2,
	},
		buffer...,
	)

	return l.device.Exchange(msgSend)
}

// NOTE: The current path prefix assumes we are using account 0 and don't have
// any change addresses
var pathPrefix = []uint32{44, 9000, 0, 0}

// collectSignatures returns an array of signatures associated with an address by index
// p1Continue -> is a flag that indicates that not all of the addresses have been signed yet so keep going
//     - if ins == INSSignHash then p1Continue == 0x01
//     - if ins == INSSignTransacton then p1Continue == 0x02
// p1CFinal -> is a flag that indicates that it is on the last address to be signed
//     - if ins == INSSignHash then p1Continue == 0x81
//     - if ins == INSSignTransacton then p1Continue == 0x82
func (l *Ledger) collectSignatures(addresses []uint32, ins byte, p1Continue byte, p1Final byte) ([][]byte, error) {
	results := make([][]byte, len(addresses))
	for i := 0; i < len(addresses); i++ {
		suffix := []uint32{addresses[i]}
		p1 := p1Continue
		if i == len(addresses)-1 {
			p1 = p1Final
		}
		data, err := bip32bytes(suffix, 0)
		if err != nil {
			return nil, err
		}
		var sendData []byte
		sendData = append(sendData, byte(len(data)))
		sendData = append(sendData, data...)
		sig, err := l.SendToLedger(CLA, ins, p1, 0x00, sendData)
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

func (l *Ledger) PrependLength(buffer []byte) ([]byte, error) {
	if len(buffer) == 0 {
		return nil, fmt.Errorf("could not prepend length, as buffer was empty")
	}
	retBuffer := append([]byte{byte(len(buffer))}, buffer...)
	return retBuffer, nil
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
	pathBytes, err := bip32bytes(append(pathPrefix, addressIndex), 3)
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
	}, nil
}

func (l *Ledger) getExtendedPublicKey() ([]byte, []byte, error) {
	var data []byte
	pathBytes, err := bip32bytes(pathPrefix, 3)
	if err != nil {
		return nil, nil, err
	}

	data = append(data, byte(len(pathBytes)))
	data = append(data, pathBytes...)
	response, err := l.SendToLedger(CLA, INSPromptExtPublicKey, 0x00, 0x00, data)
	if err != nil {
		return nil, nil, err
	}
	pkLen := response[0]
	chainCodeOffset := 2 + pkLen
	chainCodeLength := response[1+pkLen]
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
		}
	}
	return addrs, nil
}

// SignHash attempts to sign the [hash] with the provided path [addresses].
// [addresses] are appened to the [pathPrefix] (m/44'/9000'/0'/0).
func (l *Ledger) SignHash(hash []byte, addresses []uint32) ([][]byte, error) {
	pathBytes, err := bip32bytes(pathPrefix, 3)
	if err != nil {
		return nil, err
	}
	data := []byte{byte(len(addresses))}
	data = append(data, hash...)
	data = append(data, pathBytes...)
	data, err = l.PrependLength(data)
	if err != nil {
		return nil, err
	}
	fmt.Printf("signing hash: %X\n", hash)
	resp, err := l.SendToLedger(CLA, INSSignHash, 0x00, 0x00, data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(resp, hash) {
		return nil, fmt.Errorf("returned hash %x does not match requested %x", resp, hash)
	}

	return l.collectSignatures(addresses, INSSignHash, 0x01, 0x81)
}

func (l *Ledger) PrepareChunks(txn []byte, addresses []uint32, changePath []uint32) ([][]byte, error) {
	if len(txn) == 0 || len(addresses) == 0 {
		return nil, fmt.Errorf("the transaction buffer is empty")
	}
	var (
		chunks   [][]byte
		preamble []byte
	)

	pathBytes, err := bip32bytes(pathPrefix, 3)
	if err != nil {
		return nil, err
	}
	preamble = append(preamble, byte(len(addresses)))
	preamble = append(preamble, pathBytes...)
	if len(changePath) != 0 {
		changeBytes, err := bip32bytes(changePath, 3)
		if err != nil {
			return nil, err
		}
		preamble = append(preamble, changeBytes...)
	}
	preamble, err = l.PrependLength(preamble)
	if err != nil {
		return nil, err
	}
	chunks = append(chunks, preamble)

	remainingData := txn
	size := MaxApduSize

	for len(remainingData) > 0 {
		if len(remainingData) < MaxApduSize {
			size = len(remainingData)
		}
		thisChunk := remainingData[:size]
		remainingData = remainingData[size:]

		temp := make([]byte, 0)
		temp = append(temp, byte(len(thisChunk)))
		temp = append(temp, thisChunk...)
		chunks = append(chunks, temp)
	}

	return chunks, nil
}

// SignTransaction attempts to sign a valid tx [txn], given a path [addresses]
// This function will return a signed hash of txn and signatures or an error
func (l *Ledger) SignTransaction(txn []byte, addresses []uint32, changePath []uint32) ([]byte, [][]byte, error) {
	chunks, err := l.PrepareChunks(txn, addresses, changePath)
	if err != nil {
		return nil, nil, err
	}

	// send preamble first
	preResp, err := l.SendToLedger(CLA, INSSignTransaction, 0x00, 0x00, chunks[0])
	if err != nil {
		return nil, nil, err
	} else if len(preResp) != 0 {
		return nil, nil, fmt.Errorf("the preamble response should be empty")
	}

	lastChunkIdx := len(chunks) - 1
	for i := 1; i < lastChunkIdx; i++ {
		_, err = l.SendToLedger(CLA, INSSignTransaction, 0x01, 0x00, chunks[i])
		if err != nil {
			return nil, nil, err
		}
	}

	response, err := l.SendToLedger(CLA, INSSignTransaction, 0x81, 0x00, chunks[lastChunkIdx])
	if err != nil {
		return nil, nil, err
	}

	rawTxHash := hashing.ComputeHash256(txn)
	responseHash := response[0:hashing.HashLen]

	if !bytes.Equal(responseHash, rawTxHash) {
		return nil, nil, fmt.Errorf("returned hash %x does not match requested %x", responseHash, rawTxHash)
	}

	sigs, err := l.collectSignatures(addresses, INSSignTransaction, 0x02, 0x82)
	return responseHash, sigs, err
}
