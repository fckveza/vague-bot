package vaguebot

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	botproto "vague-bot/proto"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	x25519KeySize   = 32
	aesBlockSize    = 16
	hmacSHA256Size  = 32
	hkdfOutputBytes = 64
)

var e2eeHKDFInfo = []byte("WhatsApp Message Keys")

func generateX25519KeyPairRaw() (publicKey []byte, privateKey []byte, err error) {
	privateKey = make([]byte, x25519KeySize)
	if _, err = rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("generate x25519 private key: %w", err)
	}
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("generate x25519 public key: %w", err)
	}
	return publicKey, privateKey, nil
}

func deriveEncMACKeys(privateRaw, peerPublicRaw []byte) (encKey []byte, macKey []byte, err error) {
	if len(privateRaw) != x25519KeySize {
		return nil, nil, errors.New("invalid private key length")
	}
	if len(peerPublicRaw) != x25519KeySize {
		return nil, nil, errors.New("invalid public key length")
	}

	sharedSecret, err := curve25519.X25519(privateRaw, peerPublicRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("derive shared secret: %w", err)
	}

	salt := make([]byte, x25519KeySize)
	reader := hkdf.New(sha512.New, sharedSecret, salt, e2eeHKDFInfo)
	material := make([]byte, hkdfOutputBytes)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, nil, fmt.Errorf("derive hkdf material: %w", err)
	}

	encKey = append([]byte{}, material[:x25519KeySize]...)
	macKey = append([]byte{}, material[x25519KeySize:]...)
	return encKey, macKey, nil
}

func pkcs7Pad(input []byte, blockSize int) []byte {
	padLen := blockSize - (len(input) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	return append(input, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

func pkcs7Unpad(input []byte, blockSize int) ([]byte, error) {
	if len(input) == 0 || len(input)%blockSize != 0 {
		return nil, errors.New("invalid ciphertext padding")
	}
	padLen := int(input[len(input)-1])
	if padLen <= 0 || padLen > blockSize || padLen > len(input) {
		return nil, errors.New("invalid pkcs7 padding length")
	}
	for i := 0; i < padLen; i++ {
		if int(input[len(input)-1-i]) != padLen {
			return nil, errors.New("invalid pkcs7 padding bytes")
		}
	}
	return input[:len(input)-padLen], nil
}

func aesCBCEncrypt(key []byte, plaintext []byte) (iv []byte, ciphertext []byte, err error) {
	if len(key) != x25519KeySize {
		return nil, nil, errors.New("invalid AES key length")
	}
	iv = make([]byte, aesBlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("init AES cipher: %w", err)
	}
	padded := pkcs7Pad(plaintext, aesBlockSize)
	padded = pkcs7Pad(padded, aesBlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return iv, ciphertext, nil
}

func aesCBCDecrypt(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != x25519KeySize {
		return nil, errors.New("invalid AES key length")
	}
	if len(iv) != aesBlockSize {
		return nil, errors.New("invalid IV length")
	}
	if len(ciphertext) == 0 || len(ciphertext)%aesBlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	plainPadded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plainPadded, ciphertext)
	plain, err := pkcs7Unpad(plainPadded, aesBlockSize)
	if err != nil {
		return nil, err
	}
	if len(plain)%aesBlockSize == 0 {
		if plain2, err2 := pkcs7Unpad(plain, aesBlockSize); err2 == nil {
			return plain2, nil
		}
	}
	return plain, nil
}

func makeHMACSHA256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func encryptPayloadForRecipient(recipientPublicRaw []byte, plaintext []byte) (*botproto.E2EEPayload, error) {
	ephemeralPublic, ephemeralPrivate, err := generateX25519KeyPairRaw()
	if err != nil {
		return nil, err
	}

	encKey, macKey, err := deriveEncMACKeys(ephemeralPrivate, recipientPublicRaw)
	if err != nil {
		return nil, err
	}
	iv, ciphertext, err := aesCBCEncrypt(encKey, plaintext)
	if err != nil {
		return nil, err
	}
	signInput := append(append([]byte{}, iv...), ciphertext...)
	tag := makeHMACSHA256(macKey, signInput)

	return &botproto.E2EEPayload{
		EphemeralPublicKey: ephemeralPublic,
		Iv:                 iv,
		Ciphertext:         ciphertext,
		Mac:                tag,
	}, nil
}

func decryptPayloadWithPrivateKey(privateRaw []byte, payload *botproto.E2EEPayload) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("missing encrypted payload")
	}
	if len(payload.GetEphemeralPublicKey()) != x25519KeySize {
		return nil, errors.New("invalid ephemeral public key")
	}

	encKey, macKey, err := deriveEncMACKeys(privateRaw, payload.GetEphemeralPublicKey())
	if err != nil {
		return nil, err
	}
	signInput := append(append([]byte{}, payload.GetIv()...), payload.GetCiphertext()...)
	expectedMAC := makeHMACSHA256(macKey, signInput)
	if !hmac.Equal(expectedMAC, payload.GetMac()) {
		return nil, errors.New("invalid message MAC")
	}

	return aesCBCDecrypt(encKey, payload.GetIv(), payload.GetCiphertext())
}

func encryptPayloadWithSharedKey(sharedKey []byte, plaintext []byte) (*botproto.E2EEPayload, error) {
	if len(sharedKey) != x25519KeySize {
		return nil, errors.New("invalid shared key length")
	}
	iv, ciphertext, err := aesCBCEncrypt(sharedKey, plaintext)
	if err != nil {
		return nil, err
	}

	signInput := append(append([]byte{}, iv...), ciphertext...)
	tag := makeHMACSHA256(sharedKey, signInput)
	return &botproto.E2EEPayload{
		EphemeralPublicKey: []byte{},
		Iv:                 iv,
		Ciphertext:         ciphertext,
		Mac:                tag,
	}, nil
}

func decryptPayloadWithSharedKey(sharedKey []byte, payload *botproto.E2EEPayload) ([]byte, error) {
	if len(sharedKey) != x25519KeySize {
		return nil, errors.New("invalid shared key length")
	}
	if payload == nil {
		return nil, errors.New("missing encrypted payload")
	}
	if len(payload.GetMac()) != hmacSHA256Size {
		return nil, errors.New("invalid message MAC length")
	}

	signInput := append(append([]byte{}, payload.GetIv()...), payload.GetCiphertext()...)
	expectedMAC := makeHMACSHA256(sharedKey, signInput)
	if !hmac.Equal(expectedMAC, payload.GetMac()) {
		return nil, errors.New("invalid message MAC")
	}
	return aesCBCDecrypt(sharedKey, payload.GetIv(), payload.GetCiphertext())
}
