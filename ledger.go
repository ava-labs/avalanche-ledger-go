// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/hashing"
	ledger_go "github.com/zondax/ledger-go"
)

var _ Ledger = &ledger{}

// Ledger interface for the ledger wrapper
type Ledger interface {
	Version() (version string, commit string, name string, err error)
	Address(displayHrp string, addressIndex uint32) (ids.ShortID, error)
	Addresses(numAddresses int) ([]ids.ShortID, error)
	SignHash(hash []byte, addressIndexes []uint32) ([][]byte, error)
	Disconnect() error
}

const (
	CLA                   = 0x80
	INSVersion            = 0x00
	INSPromptPublicKey    = 0x02
	INSPromptExtPublicKey = 0x03
	INSSignHash           = 0x04
)

var (
	ErrLedgerNotConnected       = errors.New("ledger is not connected")
	ErrAvalancheAppNotExecuting = errors.New("ledger is not executing avalanche app")
	ErrLedgerIsBlocked          = errors.New("ledger is blocked")
	ErrRejectedSignature        = errors.New("hash sign operation rejected by ledger user")
	ErrRejectedKeyProvide       = errors.New("public key provide operation rejected by ledger user")
)

// NOTE: The current path prefix assumes we are using account 0 and don't have
// any change addresses
var pathPrefix = []uint32{44, 9000, 0, 0}

// ledger is a wrapper around the low-level Ledger Device interface that
// provides Avalanche-specific access.
type ledger struct {
	device    ledger_go.LedgerDevice
	pk        []byte
	chainCode []byte
}

// New attempts to connect to a Ledger on the device over HID.
func New() (Ledger, error) {
	admin := ledger_go.NewLedgerAdmin()
	device, err := admin.Connect(0)
	if err != nil {
		err = mapLedgerConnectionErrors(err)
		return nil, err
	}
	return &ledger{
		device: device,
	}, nil
}

func (l *ledger) collectSignatures(addressIndexes []uint32) ([][]byte, error) {
	results := make([][]byte, len(addressIndexes))
	for i := 0; i < len(addressIndexes); i++ {
		suffix := []uint32{addressIndexes[i]}
		p1 := 0x01
		if i == len(addressIndexes)-1 {
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
			err = mapLedgerConnectionErrors(err)
			if strings.Contains(err.Error(), "[APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied") {
				err = ErrRejectedSignature
			}
			return nil, err
		}
		results[i] = sig
	}
	return results, nil
}

// Disconnect attempts to disconnect from a previously connected Ledger.
func (l *ledger) Disconnect() error {
	return l.device.Close()
}

// Version returns information about the Avalanche Ledger app. If a different
// app is open, this will return an error.
func (l *ledger) Version() (version string, commit string, name string, err error) {
	msgVersion := []byte{
		CLA,
		INSVersion,
		0x0,
		0x0,
		0x0,
	}
	rawVersion, err := l.device.Exchange(msgVersion)
	if err != nil {
		err = mapLedgerConnectionErrors(err)
		return
	}

	version = fmt.Sprintf("%d.%d.%d", rawVersion[0], rawVersion[1], rawVersion[2])
	rem := bytes.Split(rawVersion[3:], []byte{0x0})
	commit = fmt.Sprintf("%x", rem[0])
	name = string(rem[1])
	return
}

// Address returns an Avalanche address as ids.ShortID, ledger ask confirmation showing
// addresss formatted with [displayHrp] (note [displayHrp] length is restricted to 4)
//
// On the P/X-Chain, accounts are derived on the path m/44'/9000'/0'/0/n
// (where n is the address index).
func (l *ledger) Address(displayHrp string, addressIndex uint32) (ids.ShortID, error) {
	if len(displayHrp) != 4 {
		return ids.ShortEmpty, fmt.Errorf("expected displayHrp len of 4, got %d", len(displayHrp))
	}
	msgPK := []byte{
		CLA,
		INSPromptPublicKey,
		0x4,
		0x0,
	}
	pathBytes, err := bip32bytes(append(pathPrefix, addressIndex), 3)
	if err != nil {
		return ids.ShortEmpty, err
	}
	data := append([]byte(displayHrp), pathBytes...)
	msgPK = append(msgPK, byte(len(data)))
	msgPK = append(msgPK, data...)
	rawAddress, err := l.device.Exchange(msgPK)
	if err != nil {
		err = mapLedgerConnectionErrors(err)
		if strings.Contains(err.Error(), "[APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied") {
			err = ErrRejectedKeyProvide
		}
		return ids.ShortEmpty, err
	}
	return ids.ToShortID(rawAddress)
}

func (l *ledger) getExtendedPublicKey() ([]byte, []byte, error) {
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
		err = mapLedgerConnectionErrors(err)
		if strings.Contains(err.Error(), "[APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied") {
			err = ErrRejectedKeyProvide
		}
		return nil, nil, err
	}
	pkLen := response[0]
	chainCodeOffset := 2 + pkLen
	chainCodeLength := response[1+pkLen]
	return response[1 : 1+pkLen], response[chainCodeOffset : chainCodeOffset+chainCodeLength], nil
}

// Addresses returns the first [numAddresses] ledger addresses as []ids.ShortID
//
// On the P/X-Chain, accounts are derived on the path m/44'/9000'/0'/0/n
// (where n is the address index).
func (l *ledger) Addresses(numAddresses int) ([]ids.ShortID, error) {
	if len(l.pk) == 0 {
		pk, chainCode, err := l.getExtendedPublicKey()
		if err != nil {
			return nil, err
		}
		l.pk = pk
		l.chainCode = chainCode
	}

	addrs := make([]ids.ShortID, numAddresses)
	for i := 0; i < numAddresses; i++ {
		k, err := NewChild(l.pk, l.chainCode, uint32(i))
		if err != nil {
			return nil, err
		}
		shortAddr, err := ids.ToShortID(hashing.PubkeyBytesToAddress(k))
		if err != nil {
			return nil, err
		}
		addrs[i] = shortAddr
	}
	return addrs, nil
}

// SignHash attempts to sign the [hash] with the provided path [addresses].
// [addressIndexes] are appened to the [pathPrefix] (m/44'/9000'/0'/0).
func (l *ledger) SignHash(hash []byte, addressIndexes []uint32) ([][]byte, error) {
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
	data := []byte{byte(len(addressIndexes))}
	data = append(data, hash...)
	data = append(data, pathBytes...)
	msgHash = append(msgHash, byte(len(data)))
	msgHash = append(msgHash, data...)
	resp, err := l.device.Exchange(msgHash)
	if err != nil {
		err = mapLedgerConnectionErrors(err)
		if strings.Contains(err.Error(), "[APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied") {
			err = ErrRejectedSignature
		}
		return nil, err
	}
	if !bytes.Equal(resp, hash) {
		return nil, fmt.Errorf("returned hash %x does not match requested %x", resp, hash)
	}

	return l.collectSignatures(addressIndexes)
}

func mapLedgerConnectionErrors(err error) error {
	if strings.Contains(err.Error(), "LedgerHID device") && strings.Contains(err.Error(), "not found") {
		return ErrLedgerNotConnected
	}
	if strings.Contains(err.Error(), "Error code: 6e01") {
		return ErrAvalancheAppNotExecuting
	}
	if strings.Contains(err.Error(), "Error code: 6b0c") {
		return ErrLedgerIsBlocked
	}
	return err
}
