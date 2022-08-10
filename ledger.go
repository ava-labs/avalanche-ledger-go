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
	MAX_APDU_SIZE         = 250
)

// NOTE: The current path prefix assumes we are using account 0 and don't have
// any change addresses
var pathPrefix = []uint32{44, 9000, 0, 0}

func (l *Ledger) collectSignatures(addresses []uint32) ([][]byte, error) {
	results := make([][]byte, len(addresses))
	for i := 0; i < len(addresses); i++ {
		suffix := []uint32{addresses[i]}
		p1 := 0x01
		if i == len(addresses)-1 {
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
	msgEPK := []byte{
		CLA,
		INSPromptExtPublicKey,
		0x0,
		0x0,
	}
	pathBytes, err := bip32bytes(pathPrefix, 3)
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
	data := []byte{byte(len(addresses))}
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

	return l.collectSignatures(addresses)
}

func (l *Ledger) PrepareChunks(txn []byte, addresses []uint32, changePath []uint32) ([][]byte, error) {
	if txn == nil || addresses == nil {
		return nil, fmt.Errorf("chunks structure is undefined")
	}
	var chunks [][]byte
	var preamble []byte
	chunk_num := 0

	pathBytes, err := bip32bytes(pathPrefix, 3)
	if err != nil {
		return nil, err
	}
	preamble = append(preamble, byte(len(addresses)))
	preamble = append(preamble, pathBytes...)
	if changePath != nil {
		changeBytes, err := bip32bytes(changePath, 3)
		if err != nil {
			return nil, err
		}
		preamble = append(preamble, changeBytes...)
	}
	preamble = append([]byte{byte(len(preamble))}, preamble...)
	chunks = append(chunks, preamble)
	chunk_num++

	fmt.Printf("Preamble: %x\n", chunks[0])

	remainingData := txn
	size := MAX_APDU_SIZE

	for len(remainingData) > 0 {
		if len(remainingData) < MAX_APDU_SIZE {
			size = len(remainingData)
		}
		thisChunk := remainingData[0:size]
		remainingData = remainingData[size:]

		temp := make([]byte, 0)
		temp = append(temp, byte(len(thisChunk)))
		temp = append(temp, thisChunk...)
		chunks = append(chunks, temp)
		chunk_num++
	}
	fmt.Printf("chunk1: %x\nchunk2: %x\nchunk3: %x\n", chunks[0], chunks[1], chunks[2])
	return chunks, nil
}

//SignTransaction attempts to sign a valid tx [txn], given a path [addresses]
//
//This function will return a signed hash of txn and signatures or an error
func (l *Ledger) SignTransaction(txn []byte, addresses []uint32, changePath []uint32) ([]byte, [][]byte, error) {
	if txn == nil || addresses == nil {
		return nil, nil, fmt.Errorf("transaction or addresses was null")
	}

	var response []byte

	chunks, err := l.PrepareChunks(txn, addresses, changePath)
	if err != nil {
		return nil, nil, err
	}

	chunk_idx := 0
	chunk_num := len(chunks)

	msgTx := []byte{
		CLA,
		INSSignTransaction,
		0x00,
		0x00,
	}

	//send preamble first
	msgTx = append(msgTx, chunks[chunk_idx]...)
	chunk_idx++
	preResp, err := l.device.Exchange(msgTx)
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("Preamble reponse: %x\n", preResp)

	if chunk_idx == chunk_num {
		msgTx = []byte{
			CLA,
			INSSignTransaction,
			0x02,
			0x00,
		}
		msgTx = append(msgTx, chunks[chunk_idx]...)
		response, err = l.device.Exchange(msgTx)
		if err != nil {
			return nil, nil, err
		}
	} else {
		for chunk_idx < chunk_num {
			msgTx = []byte{
				CLA,
				INSSignTransaction,
				0x01,
				0x00,
			}
			msgTx = append(msgTx, chunks[chunk_idx]...)
			txnResp, err := l.device.Exchange(msgTx)
			if err != nil {
				return nil, nil, err
			}
			response = append(response, txnResp...)
			chunk_idx++
			if chunk_idx == chunk_num {
				msgTx = []byte{
					CLA,
					INSSignTransaction,
					0x02,
					0x00,
				}
				msgTx = append(msgTx, chunks[chunk_idx]...)
				txnResp, err = l.device.Exchange(msgTx)
				if err != nil {
					return nil, nil, err
				}
				response = append(response, txnResp...)
			}
		}
	}

	rawTxHash := hashing.ComputeHash256(txn)
	responseHash := response[0:32]

	if !bytes.Equal(responseHash, rawTxHash) {
		return nil, nil, fmt.Errorf("returned hash %x does not match requested %x", responseHash, rawTxHash)
	}

	sigs, err := l.collectSignatures(addresses)
	if err != nil {
		return nil, nil, err
	}

	return responseHash, sigs, nil
}
