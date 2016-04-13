package cmd

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
)

// secretCmd represents the secret command
var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "perform an operation on a secret",
	Long:  `Operate on a secret within the conspiracy.`,
}

var showSecretCmd = &cobra.Command{
	Use:   "show <secret>",
	Short: "show the value of the secret",
	Long:  "Show the contents of the secret stored in the vault.",
	Run:   showSecret,
}

func Prompt(keys []openpgp.Key, symmetric bool) (pass []byte, err error) {

	if os.Getenv("GPG_AGENT_INFO") != "" {
		fmt.Println("Will try GPG agent.")

		c, err := NewGpgAgentConn()
		if err != nil {
			fmt.Printf("Couldn't open GpgAgent even though GPG_AGENT_INFO is set\n%v\n", err)
			os.Exit(-1)
		}

		pr := &PassphraseRequest{"key", "Custom error", "Passphrase", "For descr file", false}
		spass, err := c.GetPassphrase(pr)

		pass = []byte(spass)
	} else {

		fmt.Println("Enter passphrase: ")
		pass, err = gopass.GetPasswd()
	}
	if err != nil {
		fmt.Printf("No passphrase provided\n%v\n", err)
		os.Exit(-1)
	}

	for _, key := range keys {
		//fmt.Printf("Try key %X\n", key.PublicKey.KeyId)

		err := key.PrivateKey.Decrypt(pass)
		if err != nil {
			fmt.Println("  wrong")
		}
	}

	err = nil
	return
}

func showSecret(cmd *cobra.Command, args []string) {

	if Verbose {
		fmt.Printf("\nConfiguration:\n")
		fmt.Println("  Using secret keyring:  " + SecRingPath)
		fmt.Println("  Using public keyring:  " + PubRingPath)
		fmt.Println("  Using vault directory: " + VaultDir)
	}

	// Open the private key file
	keyringFile, err := os.Open(SecRingPath)
	defer keyringFile.Close()
	if err != nil {
		fmt.Printf("Couldn't open secret keyring file %v\n%v\n", SecRingPath, err)
		os.Exit(-1)
	}

	entityList, err := openpgp.ReadKeyRing(keyringFile)
	if err != nil {
		fmt.Printf("Couldn't read secret keyring file %v\n%v\n", SecRingPath, err)
		os.Exit(-1)
	}

	file, err := os.Open("vault/test.asc")
	if err != nil {
		fmt.Printf("Couldn't read secret file %v\n%v\n", "vault/test.asc", err)
		os.Exit(-1)
	}

	block, err := armor.Decode(file)
	if err != nil {
		fmt.Printf("Couldn't decode file %v\n%v\n", "vault/test.asc", err)
		os.Exit(-1)
	}

	md, err := openpgp.ReadMessage(block.Body, entityList, Prompt, nil)
	if err != nil {
		fmt.Printf("Couldn't deccrypt file %v\n%v\n", "vault/test.asc", err)
		os.Exit(-1)
	}

	if Verbose {
		for _, k := range md.EncryptedToKeyIds {
			fmt.Printf("  Encrypted for %X\n", k)
		}
	}

	if _, err := io.Copy(os.Stdout, md.UnverifiedBody); err != nil {
		panic(fmt.Sprintf("Error reading unencrypted body: %v\n", err))
	}

}

func init() {
	RootCmd.AddCommand(secretCmd)
	secretCmd.AddCommand(showSecretCmd)
}
