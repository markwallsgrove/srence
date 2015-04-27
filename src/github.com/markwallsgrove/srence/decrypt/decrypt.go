package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
)

func loadRSAPrivateKey(fileLoc string) (*rsa.PrivateKey, error) {
	pemData, err := ioutil.ReadFile(fileLoc)
	if err != nil {
		return &rsa.PrivateKey{}, err
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return &rsa.PrivateKey{}, err
	}

	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return &rsa.PrivateKey{}, err
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return &rsa.PrivateKey{}, err
	}

	return priv, nil
}

func decryptWithRSAPrivate(privateKey *rsa.PrivateKey, content []byte) ([]byte, error) {
	label := []byte("") // TODO: why do we need a label?
	out, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, content, label)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func decryptWithAESKey(iv []byte, key []byte, encryptedContent []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	content := make([]byte, len(encryptedContent))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(content, encryptedContent)

	return content, nil
}

func loadContentFromFile(fileLoc string) ([]byte, []byte, error) {
	cipherEncodedBytes, err := ioutil.ReadFile(fileLoc)
	if err != nil {
		return nil, nil, err
	}

	cipherBytes, err := base64.URLEncoding.DecodeString(string(cipherEncodedBytes))
	if err != nil {
		return nil, nil, err
	}

	// TODO: 256 is the SSH-RSA key length
	return cipherBytes[:256], cipherBytes[256:], nil
}

// TODO: decrypt file into a buffer file, cannot just use memory
func DecryptFile(fileLoc string, privateKeyLoc string) error {
	// Load RSA private key
	privateKey, err := loadRSAPrivateKey("id_rsa")
	if err != nil {
		return err
	}

	// Load file and split into chunks
	headerRSAEncrypted, bodyAESEncrypted, err := loadContentFromFile("./hack.enc")
	if err != nil {
		return err
	}

	// Decrypt header with RSA private key
	header, err := decryptWithRSAPrivate(privateKey, headerRSAEncrypted)
	if err != nil {
		return err
	}

	// Decrypt body with IV & AES key
	aesKey, iv := header[:32], header[32:]
	content, err := decryptWithAESKey(iv, aesKey, bodyAESEncrypted)
	if err != nil {
		return err
	}

	file, err := os.Create(fileLoc)
	if err != nil {
		return err
	}

	file.Write(content)
	return file.Close()
}
