package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io/ioutil"
)

func RetrieveSecret(aesKey string) error {
	encryptedData, err := ioutil.ReadFile("secret.txt")
	if err != nil {
		return err
	}

	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return err
	}

	if len(encryptedData) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptedData, encryptedData)

	fmt.Println(string(encryptedData))
	return nil
}
