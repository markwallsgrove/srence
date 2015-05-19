package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	stdErrors "errors"
	"github.com/markwallsgrove/srence/errors"
	"io"
	"io/ioutil"
	"os"
)

func loadRSAPrivateKey(fileLoc string) (*rsa.PrivateKey, error) {
	pemData, err := ioutil.ReadFile(fileLoc)
	if err != nil {
		return &rsa.PrivateKey{}, errors.Wrap("Unknown RSA Private Key", err)
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return &rsa.PrivateKey{}, err
	}

	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return &rsa.PrivateKey{}, errors.Wrap("Unknown Private Key Type", err)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return &rsa.PrivateKey{}, errors.Wrap("Cannot parse PKCS Private Key", err)
	}

	return priv, nil
}

func decryptWithRSAPrivate(privateKey *rsa.PrivateKey, content []byte) ([]byte, error) {
	label := []byte("")
	out, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, content, label)
	if err != nil {
		return nil, errors.Wrap("Cannot decrypt message", err)
	}

	return out, nil
}

func decryptWithAESKey(iv []byte, key []byte, encryptedFile *os.File, destinationLoc string) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return errors.Wrap("New AES decryption cipher", err)
	}

	outFile, err := os.OpenFile(destinationLoc, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap("Cannot create destination file", err)
	}
	defer outFile.Close()

	stream := cipher.NewOFB(block, iv)
	reader := cipher.StreamReader{S: stream, R: encryptedFile}

	if _, err := io.Copy(outFile, reader); err != nil {
		return errors.Wrap("Cannot copy encrypted file", err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.

	return nil
}

func loadHeaderFromFile(encryptedFile *os.File, headerLength int) ([]byte, error) {
	encryptedHeader := make([]byte, headerLength)
	n, err := encryptedFile.Read(encryptedHeader)

	if n != headerLength {
		return nil, stdErrors.New("Did not read enough data from encrypted file")
	} else if err != nil {
		return nil, errors.Wrap("Cannot read encrypted file", err)
	}

	return encryptedHeader, nil
}

func DecryptFile(encryptedFile *os.File, destinationLoc string, privateKeyLoc string) error {
	// Load RSA private key
	privateKey, err := loadRSAPrivateKey("id_rsa")
	if err != nil {
		return err
	}

	// Load file and split into chunks
	headerRSAEncrypted, err := loadHeaderFromFile(encryptedFile, 256) // TODO: find encrypted header length
	if err != nil {
		return err
	}

	// Decrypt header with RSA private key
	header, err := decryptWithRSAPrivate(privateKey, headerRSAEncrypted)
	if err != nil {
		return err
	}

	// Decrypt body with IV & AES key
	aesKey, iv := header[0:32], header[32:48]

	err = decryptWithAESKey(iv, aesKey, encryptedFile, destinationLoc)
	if err != nil {
		return err
	}

	encryptedFile.Close()
	return nil
}
