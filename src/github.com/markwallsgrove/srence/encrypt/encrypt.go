package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"github.com/ianmcmahon/encoding_ssh"
	"github.com/markwallsgrove/srence/errors"
	"io"
	"io/ioutil"
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

func encryptWithRSAPublicKey(contents []byte, key *rsa.PublicKey) ([]byte, error) {
	// TODO: what is a label for? I didn't think it was needed
	label := []byte("")

	out, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, contents, label)
	if err != nil {
		return nil, errors.Wrap("encrypt oaep", err)
	}

	return out, nil
}

func encryptWithAES(content []byte, iv []byte, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.Wrap("encryp aes", err)
	}

	cipherText := make([]byte, len(content))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText, content)
	return cipherText, nil
}

// TODO: encrypt file into a buffer file, cannot just use memory
func EncryptFile(file io.Reader, publicKeyBytes []byte) (string, error) {
	// Load content to be encrypted
	plainContent, err := ioutil.ReadAll(file)
	if err != nil {
		return "", errors.Wrap("read file", err)
	}

	// Convert key from ssh-rsa to rsa public key
	pubKey, err := convertSSHRSAToRSA(publicKeyBytes)
	if err != nil {
		return "", err
	}

	// Generate random key to use for AES
	aesKey, err := generateRandomString(32) // 32 bytes === AES-256
	if err != nil {
		return "", err
	}

	// Generate random iv to use with AES.
	// IV is used to encrypt the first block to provide randomness,
	// else the first block will always be the same
	iv, err := generateRandomString(aes.BlockSize) // 16 bytes
	if err != nil {
		return "", err
	}

	// Encrypt random key with RSA public key
	plainHeader := append(aesKey, iv...)
	byteHeader, err := encryptWithRSAPublicKey(plainHeader, pubKey)
	if err != nil {
		return "", err
	}

	// Encrypt content with AES
	byteCipherText, err := encryptWithAES(plainContent, iv, aesKey)
	if err != nil {
		return "", err
	}

	// Output to stdout
	encodedContent := base64.URLEncoding.EncodeToString(append(byteHeader, byteCipherText...))
	return encodedContent, nil
}
