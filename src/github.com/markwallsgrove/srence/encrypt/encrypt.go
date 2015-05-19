package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"github.com/ianmcmahon/encoding_ssh"
	"github.com/markwallsgrove/srence/errors"
	"io"
	"io/ioutil"
	"os"
)

func generateRandomString(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, errors.Wrap("generate random string", err)
	}

	return b, nil
}

func convertSSHRSAToRSA(bytes []byte) (*rsa.PublicKey, error) {
	// Decode the ssh-rsa public key
	pubKey, err := ssh.DecodePublicKey(string(bytes))
	if err != nil {
		return nil, errors.Wrap("convert ssh to rsa", err)
	}

	// Marshal to ASN.1 DER encoding
	pkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, errors.Wrap("marshal asn to der", err)
	}

	// ParsePKIXPublicKey parses a DER encoded public key to RSA
	key, err := x509.ParsePKIXPublicKey(pkix)
	if err != nil {
		return nil, errors.Wrap("parse pkix", err)
	}

	return key.(*rsa.PublicKey), nil
}

func encryptWithRSAPublicKey(contents []byte, key *rsa.PublicKey) (*os.File, error) {
	label := []byte("")

	out, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, contents, label)
	if err != nil {
		return &os.File{}, errors.Wrap("encrypt oaep", err)
	}

	encFile, err := ioutil.TempFile("", "")
	if err != nil {
		return &os.File{}, errors.Wrap("TempFile", err)
	}

	encFile.Write(out)
	return encFile, nil
}

func encryptWithAES(plainFile io.Reader, iv []byte, aesKey []byte, encFile *os.File) error {
	// https://golang.org/src/crypto/cipher/example_test.go

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return errors.Wrap("New AES Cipher", err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	stream := cipher.NewOFB(block, iv)

	writer := &cipher.StreamWriter{S: stream, W: encFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, plainFile); err != nil {
		return errors.Wrap("File Copy Failure", err)
	}

	// TODO: Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. If you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.

	return nil
}

func EncryptFile(file *os.File, publicKeyBytes []byte) (*os.File, error) {
	// Convert key from ssh-rsa to rsa public key
	pubKey, err := convertSSHRSAToRSA(publicKeyBytes)
	if err != nil {
		return &os.File{}, err
	}

	// Generate random key to use for AES
	aesKey, err := generateRandomString(32) // 32 bytes === AES-256
	if err != nil {
		return &os.File{}, err
	}

	// Generate random iv to use with AES.
	// IV is used to encrypt the first block to provide randomness,
	// else the first block will always be the same
	iv, err := generateRandomString(aes.BlockSize) // 16 bytes
	if err != nil {
		return &os.File{}, err
	}

	// Encrypt random key with RSA public key
	plainHeader := append(aesKey, iv...)
	encFile, err := encryptWithRSAPublicKey(plainHeader, pubKey)
	if err != nil {
		return &os.File{}, err
	}

	// Encrypt content with AES
	err = encryptWithAES(file, iv, aesKey, encFile)
	if err != nil {
		return &os.File{}, err
	}

	return encFile, nil
}
