package main

import (
	"encoding/binary"
	"fmt"

	"github.com/ava-labs/avalanchego/utils/formatting"
	"github.com/zondax/ledger-go"
)

const (
	CLA                   = 0x80
	INS_PROMPT_PUBLIC_KEY = 0x02
	HRP                   = "fuji"
	HARDEN_COUNT          = 3
)

func bip32bytes(bip32Path []uint32) ([]byte, error) {
	message := make([]byte, 41)
	if len(bip32Path) > 10 {
		return nil, fmt.Errorf("maximum bip32 depth = 10")
	}
	message[0] = byte(len(bip32Path))
	for index, element := range bip32Path {
		pos := 1 + index*4
		value := element
		if index < HARDEN_COUNT {
			value = 0x80000000 | element
		}
		binary.BigEndian.PutUint32(message[pos:], value)
	}
	return message, nil
}
func main() {
	admin := ledger_go.NewLedgerAdmin()
	device, err := admin.Connect(0)
	if err != nil {
		panic(err)
	}
	msg := []byte{
		CLA,
		INS_PROMPT_PUBLIC_KEY,
		0x4,
		0x00,
	}
	data := []byte(HRP)
	// "44'/9000'/0'/0/0
	pathBytes, err := bip32bytes([]uint32{44, 9000, 0, 0, 0})
	if err != nil {
		panic(err)
	}
	data = append(data, pathBytes[:21]...)
	msg = append(msg, byte(len(data)))
	msg = append(msg, data...)
	resp, err := device.Exchange(msg)
	if err != nil {
		panic(err)
	}
	addr, err := formatting.FormatBech32(HRP, resp)
	if err != nil {
		panic(err)
	}
	fmt.Println("address", addr)
}
