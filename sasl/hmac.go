package sasl

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

var (
	errEmptyBuffer                = fmt.Errorf("ERROR: Empty buffer")
	errBufferTooSmall             = fmt.Errorf("ERROR: Given buffer is too small")
	errPeerSequenceNumberMismatch = fmt.Errorf("ERROR: Peer sequence number mismatch")
	errInvalidPeerHMAC            = fmt.Errorf("ERROR: Invalid peer HMAC")
)

type cipherType int

const (
	cipherNone cipherType = iota
	cipherRC4_40
	cipherRC4_56
	cipherRC4
	cipherDES
	cipher3DES
	_cipherCount
)

type securityIntegrityContext struct {
	SeqNum     uint32
	PeerSeqNum uint32
	Ki         []byte
	PeerKi     []byte
	EncKey     []byte
	DecKey     []byte
	HA1        []byte
}

type securityPrivacyContext struct {
	securityIntegrityContext
	cipher    cipherType
	blockSize int
	EncCipher func(dst, src []byte)
	DecCipher func(dst, src []byte)
}

func (sec *securityPrivacyContext) generateKeys() error {
	ha1len := 16
	if sec.cipher == cipherRC4_40 {
		ha1len = 5
	} else if sec.cipher == cipherRC4_56 {
		ha1len = 7
	}

	sec.EncKey = md5Sum(sec.HA1, []byte(sealingClientServer))
	sec.DecKey = md5Sum(sec.HA1, []byte(sealingServerClient))
	sec.Ki = md5Sum(sec.HA1[0:ha1len], []byte(signingClientServer))
	sec.PeerKi = md5Sum(sec.HA1[0:ha1len], []byte(signingServerClient))

	switch sec.cipher {
	case cipherRC4_40, cipherRC4_56, cipherRC4:
		sec.blockSize = 1
		cipher, err := rc4.NewCipher(sec.DecKey)
		if err != nil {
			return err
		}
		sec.DecCipher = cipher.XORKeyStream
		cipher, err = rc4.NewCipher(sec.EncKey)
		if err != nil {
			return err
		}
		sec.EncCipher = cipher.XORKeyStream
	case cipher3DES:
		block, err := des.NewTripleDESCipher(sec.DecKey)
		if err != nil {
			return err
		}
		sec.blockSize = block.BlockSize()
		sec.DecCipher = block.Decrypt
		block, err = des.NewTripleDESCipher(sec.EncKey)
		if err != nil {
			return err
		}
		sec.EncCipher = block.Encrypt
	case cipherDES:
		block, err := des.NewCipher(sec.DecKey)
		if err != nil {
			return err
		}
		sec.blockSize = block.BlockSize()
		sec.DecCipher = cipher.NewCTR(block, sec.DecKey[len(sec.DecKey)-8:]).XORKeyStream
		block, err = des.NewCipher(sec.EncKey)
		if err != nil {
			return err
		}
		sec.EncCipher = cipher.NewCTR(block, sec.EncKey[len(sec.EncKey)-8:]).XORKeyStream
	default:
		return fmt.Errorf("No such cipher")
	}
	return nil
}

func (sec *securityIntegrityContext) generateKeys() error {
	sec.EncKey = md5Sum(sec.HA1, []byte(sealingClientServer))
	sec.DecKey = md5Sum(sec.HA1, []byte(sealingServerClient))
	sec.Ki = md5Sum(sec.HA1, []byte(signingClientServer))
	sec.PeerKi = md5Sum(sec.HA1, []byte(signingServerClient))
	return nil
}

func (sec *securityIntegrityContext) getHMAC(msg []byte) []byte {
	x := hmac.New(md5.New, sec.Ki)
	binary.Write(x, binary.BigEndian, sec.SeqNum)
	x.Write(msg)
	return x.Sum(nil)[0:10]
}

func (sec *securityIntegrityContext) getPeerHMAC(msg []byte) []byte {
	x := hmac.New(md5.New, sec.PeerKi)
	binary.Write(x, binary.BigEndian, sec.PeerSeqNum)
	x.Write(msg)
	return x.Sum(nil)[0:10]
}

func (sec *securityIntegrityContext) Unwrap(data []byte) (out []byte, err error) {
	if data == nil || len(data) <= 16 {
		return nil, errBufferTooSmall
	}
	sec.PeerSeqNum++
	b := bytes.NewBuffer(data[len(data)-16:])
	hmac := make([]byte, 10)
	if _, err := b.Read(hmac); err != nil {
		return nil, err
	}

	msg := make([]byte, 2)
	if _, err := b.Read(msg); err != nil {
		return nil, err
	}

	var seqNum uint32
	if err := binary.Read(b, binary.BigEndian, &seqNum); err != nil {
		return nil, err
	}

	if seqNum != sec.PeerSeqNum {
		return nil, errPeerSequenceNumberMismatch
	}

	data = data[0 : len(data)-16]
	expectedHMAC := sec.getPeerHMAC(data)
	if bytes.Compare(expectedHMAC, hmac) != 0 {
		return nil, errInvalidPeerHMAC
	}

	return data, nil
}

func (sec *securityIntegrityContext) Wrap(data []byte) (out []byte, err error) {
	if data == nil || len(data) == 0 {
		return nil, errEmptyBuffer
	}
	sec.SeqNum++
	b := bytes.NewBuffer(data)
	b.Write(sec.getHMAC(data))
	b.Write(data[0:1])
	binary.Write(b, binary.BigEndian, sec.SeqNum)
	return b.Bytes(), nil
}

func (sec *securityPrivacyContext) Unwrap(data []byte) (out []byte, err error) {
	if data == nil || len(data) <= 6 {
		return nil, errBufferTooSmall
	}
	sec.PeerSeqNum++
	b := bytes.NewBuffer(data[len(data)-6:])
	msg := make([]byte, 2)
	if _, err := b.Read(msg); err != nil {
		return nil, err
	}

	var seqNum uint32
	if err := binary.Read(b, binary.BigEndian, &seqNum); err != nil {
		return nil, err
	}

	if sec.PeerSeqNum != seqNum {
		return nil, errPeerSequenceNumberMismatch
	}

	data = data[:len(data)-6]
	out = make([]byte, len(data))
	sec.DecCipher(data, out)
	hmac := out[len(out)-10:]
	out = out[:len(hmac)]

	expectedHMAC := sec.getPeerHMAC(out)
	if bytes.Compare(expectedHMAC, hmac) != 0 {
		return nil, errInvalidPeerHMAC
	}

	return out, nil
}

func (sec *securityPrivacyContext) Wrap(data []byte) (out []byte, err error) {
	if data == nil || len(data) == 0 {
		return nil, errEmptyBuffer
	}
	sec.SeqNum++
	hmac := sec.getHMAC(data)

	length := len(data)
	padding := []byte{}
	if sec.blockSize > 1 {
		pad := byte(sec.blockSize - ((length + 10) % sec.blockSize))
		padding = bytes.Repeat([]byte{pad}, int(pad))
	}
	data = bytes.Join([][]byte{data, hmac, padding}, []byte{})
	out = make([]byte, len(data))
	sec.EncCipher(data, out)

	b := bytes.NewBuffer(out)
	b.Write(data[0:1])
	binary.Write(b, binary.BigEndian, sec.SeqNum)
	return b.Bytes(), nil
}
