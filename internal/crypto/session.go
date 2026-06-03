package crypto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Direction byte

const (
	ClientToServer Direction = 'c'
	ServerToClient Direction = 's'
)

type Codec struct {
	aead cipher.AEAD
}

func RandomSessionID() ([16]byte, error) {
	var id [16]byte
	_, err := io.ReadFull(rand.Reader, id[:])
	return id, err
}

func NewCodec(secret string, sessionID [16]byte, dir Direction) (*Codec, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret must not be empty")
	}
	info := "bifrost-v1-session-" + string([]byte{byte(dir)})
	key, err := hkdf.Key(sha256.New, []byte(secret), sessionID[:], info, 32)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead}, nil
}

func (c *Codec) Seal(nonce uint64, plaintext, aad []byte) []byte {
	return c.aead.Seal(nil, nonceBytes(nonce), plaintext, aad)
}

func (c *Codec) Open(nonce uint64, ciphertext, aad []byte) ([]byte, error) {
	return c.aead.Open(nil, nonceBytes(nonce), ciphertext, aad)
}

func nonceBytes(n uint64) []byte {
	var out [12]byte
	binary.BigEndian.PutUint64(out[4:], n)
	return out[:]
}
