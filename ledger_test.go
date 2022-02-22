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
	fmt.Printf("address: %s\n", address)

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
}
