package ledger

import (
	"fmt"
	"testing"
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
	prefix := []uint32{44, 9000, 0}
	suffixes := [][]uint32{{0, 1}, {0, 3}}
	data = []byte{byte(len(suffixes))}
	rawHash := hashing.ComputeHash256([]byte{0x1, 0x2, 0x3, 0x4})
	data = append(data, rawHash...)
	pathBytes, err = bip32bytes(prefix, 3)
	if err != nil {
		panic(err)
	}
	data = append(data, pathBytes...)
	msgHash := []byte{
		CLA,
		INSSignHash,
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
	fmt.Printf("message hash: %x\n", rawHash)

	// Get Signatures
	sigs := collectSignaturesFromSuffixes(device, prefix, suffixes)
	for i, sig := range sigs {
		fmt.Printf("sigs (%v): %x\n", append(prefix, suffixes[i]...), sig)
	}

	// TODO: Sign Transaction
	// PVM: https://github.com/ava-labs/avalanchego/blob/f0a3bbb7d745be99d4970fb3b8fba3c7da87b891/vms/platformvm/tx.go#L100-L129
}
