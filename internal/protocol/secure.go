package protocol

import (
	"encoding/binary"
	"errors"

	bifrostcrypto "bifrost/internal/crypto"
)

func PacketAAD(sessionID SessionID, querySeq, nonce uint64) []byte {
	out := make([]byte, 16+8+8)
	copy(out[:16], sessionID[:])
	binary.BigEndian.PutUint64(out[16:24], querySeq)
	binary.BigEndian.PutUint64(out[24:32], nonce)
	return out
}

func EncodeSecureFrame(secret string, sessionID SessionID, dir bifrostcrypto.Direction, querySeq uint64, f Frame) ([]byte, error) {
	codec, err := bifrostcrypto.NewCodec(secret, sessionID, dir)
	if err != nil {
		return nil, err
	}
	plain, err := MarshalFrame(f)
	if err != nil {
		return nil, err
	}
	p := Packet{SessionID: sessionID, QuerySeq: querySeq, Nonce: querySeq}
	p.Ciphertext = codec.Seal(p.Nonce, plain, PacketAAD(sessionID, querySeq, p.Nonce))
	return MarshalPacket(p)
}

func DecodeSecureFrame(secret string, dir bifrostcrypto.Direction, packetBytes []byte) (Packet, Frame, error) {
	p, err := UnmarshalPacket(packetBytes)
	if err != nil {
		return Packet{}, Frame{}, err
	}
	codec, err := bifrostcrypto.NewCodec(secret, p.SessionID, dir)
	if err != nil {
		return Packet{}, Frame{}, err
	}
	plain, err := codec.Open(p.Nonce, p.Ciphertext, PacketAAD(p.SessionID, p.QuerySeq, p.Nonce))
	if err != nil {
		return Packet{}, Frame{}, err
	}
	f, err := UnmarshalFrame(plain)
	if err != nil {
		return Packet{}, Frame{}, err
	}
	if p.Nonce != p.QuerySeq {
		return Packet{}, Frame{}, errors.New("invalid nonce")
	}
	return p, f, nil
}
