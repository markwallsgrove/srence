# srence
Send & recieve encrypted files with a TNO (trust no one) mechanism

## Install
`go install github.com/markwallsgrove/srence/srence`

## Deps
```
go install github.com/ianmcmahon/encoding_ssh
go install gopkg.in/alecthomas/kingpin.v1
```

## Commands
```
bin/srence send mw@talis.com sample.txt > hack.enc
bin/srence recieve blah ./stuff.txt
```
