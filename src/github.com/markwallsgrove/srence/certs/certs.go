package certs

import (
	"crypto/md5"
	"fmt"
	"github.com/markwallsgrove/srence/config"
	"github.com/markwallsgrove/srence/server"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func retrieveFromCache(emailAddrFileLoc string, emailAddr string) ([]byte, error) {
	if _, err := os.Stat(emailAddrFileLoc); err != nil {
		return nil, err
	}

	return ioutil.ReadFile(emailAddrFileLoc)
}

func retrieveFromServer(emailAddrFileLoc string, emailAddr string) ([]byte, error) {
	cert, err := server.FindPublicCert(emailAddr)
	if err != nil {
		return nil, err
	}

	if err = ioutil.WriteFile(emailAddrFileLoc, cert, 0755); err != nil {
		log.Println("Cannot write cache file", emailAddrFileLoc, err)
	}

	return cert, nil
}

func GetCert(configuration *config.Configuration, emailAddr string) ([]byte, error) {
	h := md5.New()
	io.WriteString(h, emailAddr)
	md5Email := fmt.Sprintf("%x", h.Sum(nil))
	emailAddrPath := filepath.Join(configuration.CacheDir, fmt.Sprintf("%s.email", md5Email))

	if _, err := os.Stat(configuration.CacheDir); err != nil {
		err = os.MkdirAll(configuration.CacheDir, 0775)
		if err != nil {
			log.Println("Cannot create cache dir", configuration.CacheDir, err)
		}
	}

	if fileLoc, err := retrieveFromCache(emailAddrPath, emailAddr); err == nil {
		return fileLoc, nil
	} else {
		return retrieveFromServer(emailAddrPath, emailAddr)
	}
}
