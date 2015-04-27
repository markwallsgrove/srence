package server

import (
	"fmt"
	"github.com/markwallsgrove/srence/config"
	"io/ioutil"
	"os"
)

func FindPublicCert(emailAddr string) ([]byte, error) {
	// TODO: query local cache
	// TODO: query server for cert

	// TODO: temp

	return ioutil.ReadFile("./id_rsa.pub")
}

func SendEncryptedFile(configuration *config.Configuration, content string) error {
	fmt.Println(content)
	return nil
}

func RecieveEncryptedFile(fileId string, file *os.File) error {
	if content, err := ioutil.ReadFile("./hack.enc"); err != nil {
		return err
	} else {
		file.Write(content)
		return file.Close()
	}
}
