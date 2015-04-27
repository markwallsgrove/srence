package main

import (
	"github.com/markwallsgrove/srence/certs"
	"github.com/markwallsgrove/srence/config"
	"github.com/markwallsgrove/srence/decrypt"
	"github.com/markwallsgrove/srence/encrypt"
	"github.com/markwallsgrove/srence/server"
	"gopkg.in/alecthomas/kingpin.v1"
	"io/ioutil"
	"log"
	"os"
)

var (
	app = kingpin.New("main", "Send and recieve encrypted files")

	homeDir    = os.Getenv("HOME")
	configFile = app.Flag("config", "Config file location").Default(homeDir + "/.srence/config.json").String()

	// TODO: send a directory by tar.gz then encrypt
	cmdSend       = app.Command("send", "Send a file")
	paramReciever = cmdSend.Arg("reciever", "Whom to send the file to").Required().String()
	paramSendFile = cmdSend.Arg("file", "File to send").Required().File()

	// TODO: tighten these locations to valid paths?
	cmdRecieve   = app.Command("recieve", "Receive a file")
	paramFileId  = cmdRecieve.Arg("fileId", "File to download").String()
	paramFileLoc = cmdRecieve.Arg("fileLoc", "Download destination").String()

	// TODO: filtering?
	cmdListAwaiting = app.Command("list", "List files awaiting to be downloaded")
)

func sendFile(configuration *config.Configuration) {
	cert, err := certs.GetCert(configuration, *paramReciever)
	if err != nil {
		log.Fatalf("Cannot find certifcate: %s", err)
	}

	encryptedContent, err := encrypt.EncryptFile(*paramSendFile, cert)
	if err != nil {
		log.Fatalf("Cannot encrypt file: %s", err)
	}

	err = server.SendEncryptedFile(configuration, encryptedContent)
	if err != nil {
		log.Fatalf("Cannot send encrypted file: %s", err)
	}
}

func recieveFile(configuration *config.Configuration) {
	// TODO: paramFileLoc isn't always supplied

	tmpFileLoc, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatalf("cannot create temporary directory: %s", err)
	}

	err = server.RecieveEncryptedFile(*paramFileId, tmpFileLoc)
	if err != nil {
		log.Fatalf("Cannot recieve encrypted file: %s", err)
	}

	err = decrypt.DecryptFile(*paramFileLoc, configuration.PrivCert)
	if err != nil {
		log.Fatalf("Cannot decrypt recieved file: %s", err)
	}
}

func parseConfig(fileLoc string) *config.Configuration {
	configuration, err := config.ParseConfig(fileLoc)
	if err != nil {
		log.Fatalf("Cannot parse configuration file: %s", err)
	}

	return configuration
}

func main() {
	// TODO: how does one sign a package with a private key?
	// TODO: default configuration file must exist before executing
	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))
	configuration := parseConfig(*configFile)

	switch cmd {
	case cmdSend.FullCommand():
		sendFile(configuration)
	case cmdRecieve.FullCommand():
		recieveFile(configuration)
	}
}
