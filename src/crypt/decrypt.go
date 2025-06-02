package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"encoding/binary"
	"net/url"
)

func DecryptAES(encryptedBase32 string, key string) (string, error) {
	urlDecoded, err := url.QueryUnescape(encryptedBase32)
	if err != nil {
		return "", err
	}

	decoded, err := base32.StdEncoding.DecodeString(urlDecoded)
	if err != nil {
		return "", err
	}

	buffer := bytes.NewReader(decoded)

	var ivLen int32
	if err := binary.Read(buffer, binary.BigEndian, &ivLen); err != nil {
		return "", err
	}

	iv := make([]byte, ivLen)
	_, err = buffer.Read(iv)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, buffer.Len())
	_, err = buffer.Read(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, int(ivLen))
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
