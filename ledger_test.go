// Copyright (C) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"fmt"
	"testing"

	"github.com/ava-labs/avalanchego/utils/hashing"
)

// NOTE: You must have a physical ledger device to run this test
//
// TODO: mock + test specific correctness rather than just FATAL
func TestLedger(t *testing.T) {
	device, err := Connect()
	if err != nil {
		t.Fatal(err)
	}

	// Get version
	version, commit, name, err := device.Version()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("version: %s commit: %s name: %s\n", version, commit, name)

	// Get Fuji Address
	address, err := device.Address("fuji", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("address: %+v\n", address)

	// Get Extended Addresses
	addresses, err := device.Addresses("fuji", 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, addr := range addresses {
		fmt.Printf("address(%d): %+v\n", i, addr)
		if i == 0 && addr.Addr != address.Addr {
			t.Fatalf("address mismatch at index 0 (expected=%s, found=%s)", address.Addr, addr.Addr)
		}
	}

	// Sign Hash
	rawHash := hashing.ComputeHash256([]byte{0x1, 0x2, 0x3, 0x4})
	suffixes := [][]uint32{{0, 1}, {0, 3}}
	sigs, err := device.SignHash(rawHash, suffixes)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures but found %d", len(sigs))
	}

	// Disconnect
	if err := device.Disconnect(); err != nil {
		t.Fatal(err)
	}
}
