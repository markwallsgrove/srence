package config

import (
	"encoding/json"
	"os"
)

type Configuration struct {
	CacheDir   string
	ServerHost string
	PubCert    string
	PrivCert   string
}

func ParseConfig(fileLoc string) (*Configuration, error) {
	configuration := Configuration{}
	file, err := os.Open(fileLoc)
	if err != nil {
		return &configuration, err
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&configuration)
	if err != nil {
		return &configuration, err
	}

	return &configuration, nil
}
