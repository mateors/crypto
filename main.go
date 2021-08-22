package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
	"log"
	"time"
)

func main() {
	startingTime := time.Now()
	var err error
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var sourceText, encryptedText, decryptedText, label []byte

	// SHORT TEXT 92 bytes
	sourceText = []byte(`{347,7,3,8,7,0,7,5,6,4,1,6,5,6,7,3,7,7,7,6,5,3,5,3,3,5,4,3,2,10,3,7,5,6,65,350914,760415,33}`)
	fmt.Printf("\nsourceText byte length:\n%d\n", len(sourceText))

	// LONGER TEXT 124 bytes
	// sourceText = []byte(`{347,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,65,350914,760415,33}`)
	// fmt.Printf("\nsourceText byte length:\n%d\n", len(sourceText))

	if privateKey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		log.Fatal(err)
	}

	// fmt.Printf("\nprivateKey:\n%s\n", privateKey)

	privateKey.Precompute()

	if err = privateKey.Validate(); err != nil {
		log.Fatal(err)
	}

	publicKey = &privateKey.PublicKey

	encryptedText = encrypt(publicKey, sourceText, label)
	decryptedText = decrypt(privateKey, encryptedText, label)

	fmt.Printf("\nsourceText: \n%s\n", string(sourceText))
	fmt.Printf("\nencryptedText: \n%x\n", encryptedText)
	fmt.Printf("\ndecryptedText: \n%s\n", decryptedText)

	fmt.Printf("\nDone in %v.\n\n", time.Now().Sub(startingTime))
}

func encrypt(publicKey *rsa.PublicKey, sourceText, label []byte) (encryptedText []byte) {
	var err error
	var md5_hash hash.Hash
	md5_hash = md5.New()
	if encryptedText, err = rsa.EncryptOAEP(md5_hash, rand.Reader, publicKey, sourceText, label); err != nil {
		log.Fatal(err)
	}
	return
}

func decrypt(privateKey *rsa.PrivateKey, encryptedText, label []byte) (decryptedText []byte) {
	var err error
	var md5_hash hash.Hash
	md5_hash = md5.New()
	if decryptedText, err = rsa.DecryptOAEP(md5_hash, rand.Reader, privateKey, encryptedText, label); err != nil {
		log.Fatal(err)
	}
	return
}
