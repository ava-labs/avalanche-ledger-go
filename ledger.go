// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"errors"
	"fmt"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/hashing"
	ledger_app "github.com/zondax/ledger-avalanche-go"
)

var _ Ledger = &ledger{}

// Ledger interface for the ledger wrapper
type Ledger interface {
	Version() (version string, commit string, name string, err error)
	Address(displayHRP string, addressIndex uint32) (ids.ShortID, error)
	Addresses(addressIndices []uint32) ([]ids.ShortID, error)
	SignHash(hash []byte, addressIndices []uint32) ([][]byte, error)
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
	app       *ledger_app.LedgerAvalanche
	pubkey    []byte
	chainCode []byte
	hrp       string
	chainID   string
}

// New attempts to connect to a Ledger on the device over HID.
func New() (Ledger, error) {
	app, err := ledger_app.FindLedgerAvalancheApp()
	if err != nil {
		return nil, err
	}
	return &ledger{
		app: app,
	}, nil
}

// TODO
func NewWithChainDetails(hrp string, chainID string) (Ledger, error) {
	app, err := ledger_app.FindLedgerAvalancheApp()
	if err != nil {
		return nil, err
	}
	return &ledger{
		app:     app,
		hrp:     hrp,
		chainID: chainID,
	}, nil
}

// Disconnect attempts to disconnect from a previously connected Ledger.
func (l *ledger) Disconnect() error {
	return l.app.Close()
}

// Version returns information about the Avalanche Ledger app. If a different
// app is open, this will return an error.
func (l *ledger) Version() (version string, commit string, name string, err error) {
	info, err := l.app.GetVersion()
	if err != nil {
		return "", "", "", err
	}
	return info.String(), "", "Avalanche", nil
}

// Address returns an Avalanche address as ids.ShortID, ledger ask confirmation showing
// addresss formatted with [displayHRP] (note [displayHRP] length is restricted to 4)
//
// On the P/X-Chain, accounts are derived on the path m/44'/9000'/0'/0/n
// (where n is the address index).
func (l *ledger) Address(displayHRP string, addressIndex uint32) (ids.ShortID, error) {
	if len(l.pubkey) == 0 {
		showOnScreen := true
		path := fmt.Sprintf("%s0/%d", getRootPath(), addressIndex)
		pk, _, err := l.app.GetPubKey(path, showOnScreen, l.hrp, l.chainID)
		if err != nil {
			return ids.ShortEmpty, err
		}
		l.pubkey = pk
	}
	k, err := NewChild(l.pubkey, l.chainCode, addressIndex)
	if err != nil {
		return ids.ShortEmpty, err
	}
	return ids.ToShortID(hashing.PubkeyBytesToAddress(k))
}

// Addresses returns the ledger addresses associated to the given [addressIndices], as []ids.ShortID
//
// On the P/X-Chain, accounts are derived on the path m/44'/9000'/0'/0/n
// (where n is the address index).
func (l *ledger) Addresses(addressIndices []uint32) ([]ids.ShortID, error) {
	if len(l.pubkey) == 0 {
		showOnScreen := true
		path := getRootPath() + "/0"
		pk, _, err := l.app.GetPubKey(path, showOnScreen, l.hrp, l.chainID)
		if err != nil {
			return nil, err
		}
		l.pubkey = pk
	}

	addrs := make([]ids.ShortID, len(addressIndices))
	for i, addrIndex := range addressIndices {
		k, err := NewChild(l.pubkey, l.chainCode, addrIndex)
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
// [addressIndices] are appened to the [pathPrefix] (m/44'/9000'/0'/0).
func (l *ledger) SignHash(hash []byte, addressIndices []uint32) ([][]byte, error) {
	signingPaths := getSigningPathsFromIndices(addressIndices)
	rootPath := getRootPath()
	respSign, err := l.app.SignHash(rootPath, signingPaths, hash)
	if err != nil {
		return nil, err
	}

	if err := l.app.VerifyMultipleSignatures(*respSign, hash, rootPath, signingPaths, l.hrp, l.chainID); err != nil {
		return nil, err
	}

	sigs := make([][]byte, len(addressIndices))
	i := 0
	for _, sig := range respSign.Signature {
		sigs[i] = sig
		i++
	}
	return sigs, nil
}

func getRootPath() string {
	return fmt.Sprintf("m/%d'/%d'/%d'/", pathPrefix[0], pathPrefix[1], pathPrefix[2])
}

func getSigningPathsFromIndices(indices []uint32) []string {
	signingPaths := make([]string, len(indices))
	for i, idx := range indices {
		signingPaths[i] = fmt.Sprintf("0/%d", idx)
	}
	return signingPaths
}
