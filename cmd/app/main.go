package main

import (
	"fmt"
	"log"
	"os"

	"github.com/VitorHFernandes/CardSecure/src/crypt"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error on loading .env file")
	}

	const (
		ivSize    = 16
		intSize   = 4
		tagLength = 16
	)

	secretKey := os.Getenv("SECRET_KEY")

	if len(os.Args) == 3 {
		numero := os.Args[1]
		cpf := os.Args[2]
		json := fmt.Sprintf(`{"numeroPlastico":"%s","cpf":"%s"}`, numero, cpf)

		encrypted, err := crypt.EncryptAES(ivSize, json, secretKey)
		if err != nil {
			fmt.Println("Erro ao criptografar:", err)
			return
		}
		fmt.Println(encrypted)

	} else if len(os.Args) == 2 {
		encrypted := os.Args[1]

		decrypted, err := crypt.DecryptAES(encrypted, secretKey)
		if err != nil {
			fmt.Println("Erro ao descriptografar:", err)
			return
		}
		fmt.Println(decrypted)

	} else {
		fmt.Println("Modo de uso:")
		fmt.Println("  Criptografar: go run main.go <numeroCartao> <cpf>")
		fmt.Println("  Descriptografar: go run main.go <encrypted_id>")
	}
}
