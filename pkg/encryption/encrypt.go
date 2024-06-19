package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

func StoreSecret(secretValue string, aesKey string) error {
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return err
	}

	encryptedData := make([]byte, aes.BlockSize+len(secretValue))
	iv := encryptedData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedData[aes.BlockSize:], []byte(secretValue))

	if err := ioutil.WriteFile("secret.txt", encryptedData, 0644); err != nil {
		return err
	}

	fmt.Println("Secret set successfully!")
	return nil
}
