package server

import (
	"github.com/markwallsgrove/srence/config"
	"github.com/markwallsgrove/srence/errors"
	"io/ioutil"
	"os"
)

func FindPublicCert(emailAddr string) ([]byte, error) {
	// TODO: query local cache
	// TODO: query server for cert

	// TODO: temp

	return ioutil.ReadFile("./id_rsa.pub")
}

func SendEncryptedFile(configuration *config.Configuration, encFile *os.File) error {
	encFile.Seek(0, os.SEEK_SET)

	if content, err := ioutil.ReadAll(encFile); err != nil {
		return errors.Wrap("Read enc file", err)
	} else {
		ioutil.WriteFile("hack.enc", content, 0755)
	}

	return nil
}

func RecieveEncryptedFile(fileId string, file *os.File) error {
	if content, err := ioutil.ReadFile("./hack.enc"); err != nil {
		return err
	} else {
		file.Write(content)
		file.Seek(0, os.SEEK_SET)
		return nil
	}
}
