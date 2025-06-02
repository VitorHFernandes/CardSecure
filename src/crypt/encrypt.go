package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"encoding/binary"
	"net/url"

	"github.com/VitorHFernandes/CardSecure/utils"
)

func EncryptAES(ivSize int, json string, key string) (string, error) {
	iv, err := utils.GenerateIV(ivSize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, ivSize)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, iv, []byte(json), nil)

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, int32(ivSize))
	buffer.Write(iv)
	buffer.Write(ciphertext)

	encoded := base32.StdEncoding.EncodeToString(buffer.Bytes())
	urlEncoded := url.QueryEscape(encoded)

	return urlEncoded, nil
}
