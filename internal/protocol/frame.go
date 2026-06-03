package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version uint8 = 1

	TypeHello uint8 = iota + 1
	TypeAuth
	TypeOpen
	TypeData
	TypeWindow
	TypeACK
	TypePing
	TypePong
	TypeClose
	TypeError
)

const (
	MaxFramePayload    = 1200
	MaxQueryPayload    = 64
	MaxResponsePayload = 160
	FrameHeaderLen     = 17
)

type StreamID uint32

type Frame struct {
	Version    uint8
	Type       uint8
	Flags      uint8
	StreamID   StreamID
	Seq        uint64
	PayloadLen uint16
	Payload    []byte
}

func MarshalFrame(f Frame) ([]byte, error) {
	if f.Version == 0 {
		f.Version = Version
	}
	if f.Version != Version {
		return nil, fmt.Errorf("unsupported frame version %d", f.Version)
	}
	if len(f.Payload) > 0xffff {
		return nil, errors.New("frame payload too large")
	}
	out := make([]byte, FrameHeaderLen+len(f.Payload))
	out[0] = f.Version
	out[1] = f.Type
	out[2] = f.Flags
	binary.BigEndian.PutUint32(out[3:7], uint32(f.StreamID))
	binary.BigEndian.PutUint64(out[7:15], f.Seq)
	binary.BigEndian.PutUint16(out[15:17], uint16(len(f.Payload)))
	copy(out[17:], f.Payload)
	return out, nil
}

func UnmarshalFrame(in []byte) (Frame, error) {
	if len(in) < FrameHeaderLen {
		return Frame{}, errors.New("short frame")
	}
	f := Frame{
		Version:    in[0],
		Type:       in[1],
		Flags:      in[2],
		StreamID:   StreamID(binary.BigEndian.Uint32(in[3:7])),
		Seq:        binary.BigEndian.Uint64(in[7:15]),
		PayloadLen: binary.BigEndian.Uint16(in[15:17]),
	}
	if f.Version != Version {
		return Frame{}, fmt.Errorf("unsupported frame version %d", f.Version)
	}
	end := FrameHeaderLen + int(f.PayloadLen)
	if len(in) != end {
		return Frame{}, errors.New("invalid frame payload length")
	}
	f.Payload = append([]byte(nil), in[17:end]...)
	return f, nil
}

func TypeName(t uint8) string {
	switch t {
	case TypeHello:
		return "HELLO"
	case TypeAuth:
		return "AUTH"
	case TypeOpen:
		return "OPEN"
	case TypeData:
		return "DATA"
	case TypeWindow:
		return "WINDOW"
	case TypeACK:
		return "ACK"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeClose:
		return "CLOSE"
	case TypeError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
