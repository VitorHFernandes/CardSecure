package utils

import "crypto/rand"

func GenerateIV(ivSize int) ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	return iv, err
}
