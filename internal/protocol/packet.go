package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var packetMagic = [4]byte{'D', 'T', 'T', '1'}

const PacketHeaderLen = 4 + 16 + 8 + 8 + 2

type SessionID [16]byte

type Packet struct {
	SessionID  SessionID
	QuerySeq   uint64
	Nonce      uint64
	Ciphertext []byte
}

func MarshalPacket(p Packet) ([]byte, error) {
	if len(p.Ciphertext) > 0xffff {
		return nil, errors.New("packet ciphertext too large")
	}
	out := make([]byte, PacketHeaderLen+len(p.Ciphertext))
	copy(out[0:4], packetMagic[:])
	copy(out[4:20], p.SessionID[:])
	binary.BigEndian.PutUint64(out[20:28], p.QuerySeq)
	binary.BigEndian.PutUint64(out[28:36], p.Nonce)
	binary.BigEndian.PutUint16(out[36:38], uint16(len(p.Ciphertext)))
	copy(out[38:], p.Ciphertext)
	return out, nil
}

func UnmarshalPacket(in []byte) (Packet, error) {
	if len(in) < PacketHeaderLen {
		return Packet{}, errors.New("short packet")
	}
	if string(in[0:4]) != string(packetMagic[:]) {
		return Packet{}, errors.New("invalid packet magic")
	}
	var p Packet
	copy(p.SessionID[:], in[4:20])
	p.QuerySeq = binary.BigEndian.Uint64(in[20:28])
	p.Nonce = binary.BigEndian.Uint64(in[28:36])
	n := int(binary.BigEndian.Uint16(in[36:38]))
	if len(in) != PacketHeaderLen+n {
		return Packet{}, fmt.Errorf("invalid packet length %d want %d", len(in), PacketHeaderLen+n)
	}
	p.Ciphertext = append([]byte(nil), in[38:]...)
	return p, nil
}
