package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
)

var showSecretCmd = &cobra.Command{
	Use:   "show <secret>",
	Short: "show the value of the secret",
	Long:  "Show the contents of the secret stored in the vault.",
	Run:   showSecret,
}

func Prompt() func(keys []openpgp.Key, symmetric bool) (pass []byte, err error) {
	pass_tries := 3

	if os.Getenv("GPG_AGENT_INFO") != "" {
		// Use the GPG Agent to get the passphrase
		return func(keys []openpgp.Key, symmetric bool) (pass []byte, err error) {

			c, err1 := NewGpgAgentConn()
			if err1 != nil {
				fmt.Printf("Couldn't open GpgAgent even though GPG_AGENT_INFO is set\n%v\n", err)
				os.Exit(-1)
			}

			for _, key := range keys {

				names := make([]string, len(key.Entity.Identities))
				i := 0
				for l, _ := range key.Entity.Identities {
					names[i] = l
					i++
				}

				keyid := fmt.Sprintf("%016X", key.PublicKey.KeyId)
				pr := &PassphraseRequest{
					keyid,
					"",
					"Passphrase:",
					fmt.Sprintf("You need a passphrase to unlock the secret key for \"%s\" (%s)", strings.Join(names, " "), keyid),
					false,
				}

				spass, _ := c.GetPassphrase(pr)
				pass = []byte(spass)
				err = key.PrivateKey.Decrypt(pass)
				if err != nil {
					c.RemoveFromCache(keyid)
					pass_tries--
					if pass_tries < 1 {
						fmt.Printf("No valid passphrase after 3 tries. Quitting.\n")
						os.Exit(-1)
					}
					pr.Error = "Wrong passphrase. Please try again."
				} else {
					err = nil
					return
				}
			}
			err = errors.New("No matching key")
			return
		}

	} else {

		// Just use a simple passphrase grabber
		return func(keys []openpgp.Key, symmetric bool) (pass []byte, err error) {

			for _, key := range keys {
				names := make([]string, len(key.Entity.Identities))
				i := 0
				for l, _ := range key.Entity.Identities {
					names[i] = l
					i++
				}

				keyid := fmt.Sprintf("%016X", key.PublicKey.KeyId)

				fmt.Printf("Enter passphrase for \"%s\" (%s): ", strings.Join(names, " "), keyid)
				pass, err = gopass.GetPasswd()
				if err != nil {
					fmt.Printf("Error reading passphrase.\n%v\n", err)
					os.Exit(-1)
				}
				err = key.PrivateKey.Decrypt(pass)
				if err != nil {
					pass_tries--
					if pass_tries < 1 {
						fmt.Printf("No valid passphrase after 3 tries. Quitting.\n")
						os.Exit(-1)
					}
					fmt.Println("Wrong passphrase. Please try again.")
				} else {
					err = nil
					return
				}
			}

			err = errors.New("No matching key")
			return
		}
	}
}

func getSecret(name string) (data *bytes.Buffer) {
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

	path := filepath.Join(VaultDir, name)
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Couldn't read secret file %v\n%v\n", path, err)
		os.Exit(-1)
	}

	block, err := armor.Decode(file)
	if err != nil {
		fmt.Printf("Couldn't decode file %v\n%v\n", name, err)
		os.Exit(-1)
	}

	md, err := openpgp.ReadMessage(block.Body, entityList, Prompt(), nil)
	if err != nil {
		fmt.Printf("Couldn't decrypt secret %v\n%v\n", name, err)
		os.Exit(-1)
	}

	if Verbose {
		for _, k := range md.EncryptedToKeyIds {
			fmt.Printf("Secret encrypted for %X\n", k)
		}
	}

	data = bytes.NewBuffer(nil)
	if _, err := io.Copy(data, md.UnverifiedBody); err != nil {
		fmt.Printf("Couldn't read unencrypted data from %v\n%v\n", name, err)
		os.Exit(-1)
	}

	return

}

func showSecret(cmd *cobra.Command, args []string) {

	if Verbose {
		fmt.Printf("\nConfiguration:\n")
		fmt.Println("  Using secret keyring:  " + SecRingPath)
		fmt.Println("  Using public keyring:  " + PubRingPath)
		fmt.Println("  Using vault directory: " + VaultDir)
		fmt.Println()
	}

	if len(args) < 1 {
		fmt.Printf("You must specify a secret to show\n")
		os.Exit(0)
	}

	secret := getSecret(args[0])

	if Verbose {
		fmt.Println()
		fmt.Println("-----BEGIN UNENCRYPTED SECRET----")
	}

	if _, err := io.Copy(os.Stdout, secret); err != nil {
		fmt.Printf("Couldn't write data to StdOut\n%v\n", err)
		os.Exit(-1)
	}

	if Verbose {
		fmt.Println("-----END UNENCRYPTED SECRET----")
	}

}

func init() {
	secretCmd.AddCommand(showSecretCmd)
}
