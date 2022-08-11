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
	address, err := device.Address("fuji", 0)
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

		// Ensure first derived address matches directly requested address
		if i == 0 && addr.Addr != address.Addr {
			t.Fatalf("address mismatch at index 0 (expected=%s, found=%s)", address.Addr, addr.Addr)
		}
	}

	// Sign Hash
	rawHash := hashing.ComputeHash256([]byte{0x1, 0x2, 0x3, 0x4})
	indices := []uint32{1, 3}
	sigs, err := device.SignHash(rawHash, indices)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures but found %d", len(sigs))
	}

	// Sign Transaction
	rawTxn := []byte{ // base tx:
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x30, 0x39,
		//blockchain id
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//number of outputs
		0x00, 0x00, 0x00, 0x01,
		//output
		0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96,
		0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
		0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0,
		0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
		0xee, 0x5b, 0xe5, 0xc0, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01, 0xda, 0x2b, 0xee, 0x01,
		0xbe, 0x82, 0xec, 0xc0, 0x0c, 0x34, 0xf3, 0x61,
		0xed, 0xa8, 0xeb, 0x30, 0xfb, 0x5a, 0x71, 0x5c,
		//number of inputs
		0x00, 0x00, 0x00, 0x01,
		//input
		0xdf, 0xaf, 0xbd, 0xf5, 0xc8, 0x1f, 0x63, 0x5c,
		0x92, 0x57, 0x82, 0x4f, 0xf2, 0x1c, 0x8e, 0x3e,
		0x6f, 0x7b, 0x63, 0x2a, 0xc3, 0x06, 0xe1, 0x14,
		0x46, 0xee, 0x54, 0x0d, 0x34, 0x71, 0x1a, 0x15,
		//addresses
		0x00, 0x00, 0x00, 0x01,
		0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96,
		0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
		0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0,
		0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb,

		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x01, 0xd2, 0x97, 0xb5, 0x48, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		//memo length
		0x00, 0x00, 0x00, 0x00,
		// Node ID
		0xe9, 0x09, 0x4f, 0x73, 0x69, 0x80, 0x02, 0xfd,
		0x52, 0xc9, 0x08, 0x19, 0xb4, 0x57, 0xb9, 0xfb,
		0xc8, 0x66, 0xab, 0x80,
		// StartTime
		0x00, 0x00, 0x00, 0x00, 0x5f, 0x21, 0xf3, 0x1d,
		// EndTime
		0x00, 0x00, 0x00, 0x00, 0x5f, 0x49, 0x7d, 0xc6,
		// Weight
		0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00,
		// Stake
		0x00, 0x00, 0x00, 0x01,
		0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96,
		0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8,
		0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0,
		0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb,

		0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x3c, 0xb7, 0xd3, 0x84, 0x2e, 0x8c, 0xee, 0x6a,
		0x0e, 0xbd, 0x09, 0xf1, 0xfe, 0x88, 0x4f, 0x68,
		0x61, 0xe1, 0xb2, 0x9c,
		// RewardsOwner
		0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01, 0xda, 0x2b, 0xee, 0x01,
		0xbe, 0x82, 0xec, 0xc0, 0x0c, 0x34, 0xf3, 0x61,
		0xed, 0xa8, 0xeb, 0x30, 0xfb, 0x5a, 0x71, 0x5c,
		// Shares
		0x00, 0x00, 0x00, 0x64}

	//rawTxn := []byte{0x80, 0x00, 0x00, 0x2c, 0x80, 0x00, 0x01, 0x35, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}

	indicesTxn := []uint32{1}

	resp, txnsigs, err := device.SignTransaction(rawTxn, indicesTxn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(txnsigs) != 1 {
		t.Fatalf("expected 1 signature but found %d", len(txnsigs))
	}
	if resp == nil {
		t.Fatalf("The response hash was null")
	}
	// Disconnect
	if err := device.Disconnect(); err != nil {
		t.Fatal(err)
	}
}
