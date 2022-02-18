package main

import (
	"encoding/binary"
	"fmt"

	"github.com/djimenez/iconv-go"
	"github.com/zondax/ledger-go"
)

const (
	CLA                   = 0x80
	INS_PROMPT_PUBLIC_KEY = 0x02
)

func GetBip32bytes(bip32Path []uint32, hardenCount int) ([]byte, error) {
	message := make([]byte, 41)
	if len(bip32Path) > 10 {
		return nil, fmt.Errorf("maximum bip32 depth = 10")
	}
	message[0] = byte(len(bip32Path))
	for index, element := range bip32Path {
		pos := 1 + index*4
		value := element
		if index < hardenCount {
			value = 0x80000000 | element
		}
		binary.LittleEndian.PutUint32(message[pos:], value)
	}
	return message, nil
}

func main() {
	fmt.Println("vim-go")
	admin := ledger_go.NewLedgerAdmin()
	fmt.Println(admin.ListDevices())
	fmt.Println(admin.CountDevices())
	device, err := admin.Connect(0)
	if err != nil {
		panic(err)
	}
	msg := []byte{
		CLA,
		INS_PROMPT_PUBLIC_KEY,
		0x04,
		0x00,
	}
	data := []byte{}
	output, err := iconv.ConvertString("fuji", "utf-8", "latin1")
	if err != nil {
		panic(err)
	}
	fmt.Println(output)
	data = append(data, output...)
	bip32Bytes, err := GetBip32bytes([]uint32{44, 9000, 0, 0, 0}, 3)
	if err != nil {
		panic(err)
	}
	fmt.Println(bip32Bytes)
	data = append(data, bip32Bytes...)
	msg = append(msg, byte(len(data)))
	msg = append(msg, data...)
	fmt.Println(device.Exchange(msg))
}
