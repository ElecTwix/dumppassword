package mstate

import "unsafe"

type LocalState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

type DataBlob struct {
	CbData uint32
	PbData *byte
}

func (b *DataBlob) ToByteArray() []byte {
	d := make([]byte, b.CbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.PbData))[:])
	return d
}
