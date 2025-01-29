package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
)

func genarateprivatekey() (*rsa.PrivateKey, error) {

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, fmt.Errorf("error genarating the key : %w", err)
	}
	return privatekey, nil
}

func signatureoffile(filename string, privatekey *rsa.PrivateKey) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "error", err

	}
	hash := sha256.Sum256(content)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privatekey, crypto.SHA256, hash[:])
	return string(signature), err
}

func signnatureverification(filename string, signature []byte, publickey *rsa.PublicKey) error {

	content, err := os.ReadFile(filename)

	if err != nil {
		return fmt.Errorf("error reading the file : %w", err)

	}
	hash := sha256.Sum256(content)

	err = rsa.VerifyPKCS1v15(publickey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("error verifying the file : %w", err)
	}
	fmt.Println("signature is valid !!")
	return nil
}

// func displaycontentinfile(filename string) error {

// 	file, err := os.Open(filename)
// 	if err != nil {

// 		return fmt.Errorf("error in opening the file : %w", err)

// 	}

// 	content, err := io.ReadAll(file)
// 	if err != nil {

// 		return fmt.Errorf("error in reading the file : %w", err)

// 	}

// 	fmt.Println("Input given by user :")

// 	fmt.Println(string(content))
// 	return nil
// }

func main() {
	privateKey, err := genarateprivatekey()
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	fmt.Println("Private key generated successfully:", privateKey)
	filename := "test.txt"
	signature, _ := signatureoffile(filename, privateKey)
	fmt.Println(signature)

	publicKey := &privateKey.PublicKey

	err = signnatureverification(filename, []byte(signature), publicKey)
	if err != nil {
		fmt.Println("error in verification of the file", err)
	} else {
		fmt.Println(" Signature verification successful!! ")
	}
	// displaycontentinfile(filename)
}
