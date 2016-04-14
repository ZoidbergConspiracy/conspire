package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/spf13/cobra"
)

var editSecretCmd = &cobra.Command{
	Use:   "edit <secret>",
	Short: "edit the value of the secret",
	Long: `Edit the contents of the secret stored in the vault.
Creates a new secret if one doesn't already exist.`,
	Run: editSecret,
}

var recryptSecretCmd = &cobra.Command{
	Use:   "recrypt <secret>",
	Short: "recrypt the value of the secret",
	Long: `Recrypt the contents of the secret stored in the vault.
This is useful to update a secret after you change group members.`,
	Run: recryptSecret,
}

var group string

func init() {
	secretCmd.AddCommand(editSecretCmd)
	secretCmd.AddCommand(recryptSecretCmd)
	editSecretCmd.Flags().StringVarP(&group, "group", "g", "default", "group to whom the secret will be encrypted")
	editSecretCmd.Flags().StringVarP(&Editor, "editor", "e", os.Getenv("EDITOR"), "editor to use")
}

func recryptSecret(cmd *cobra.Command, args []string) {

	if Verbose {
		fmt.Printf("\nConfiguration:\n")
		fmt.Println("  Using secret keyring:  " + SecRingPath)
		fmt.Println("  Using public keyring:  " + PubRingPath)
		fmt.Println("  Using vault directory: " + VaultDir)
	}
	if len(args) < 1 {
		fmt.Printf("You must specify a secret to recrypt\n")
		os.Exit(0)
	}

	name := args[0]
	spath := filepath.Join(VaultDir, name)
	file, err := os.OpenFile(spath, os.O_RDWR, 0660)
	if err != nil {
		fmt.Printf("Couldn't open secret file %v\n%v\n", spath, err)
		os.Exit(-1)
	}

	secret := getSecret(name)

	// Create a temporary file and copy the secret in
	base := ".tmp." + path.Base(spath)
	tmpfile, err := ioutil.TempFile(VaultDir, base)
	if err != nil {
		fmt.Printf("Couldn't create secure temporary file in %v\n%v\n", VaultDir, err)
		os.Exit(-1)
	}
	tmpname := tmpfile.Name()

	if _, err := io.Copy(tmpfile, secret); err != nil {
		fmt.Printf("Couldn't write secret data into temp file %v\n%v\n", tmpname, err)
		os.Exit(-1)
	}
	tmpfile.Close()

	// Encrypt the temporary file and overwrite the previous secret
	tmpfile, err = os.Open(tmpname)
	if err != nil {
		fmt.Printf("Couldn't read back contents of edited buffer %v\n%v\n", tmpname, err)
		os.Exit(-1)
	}
	raw := new(bytes.Buffer)
	if _, err := raw.ReadFrom(tmpfile); err != nil {
		fmt.Printf("Couldn't read data from %v into buffer\n%v\n", tmpname, err)
		os.Exit(-1)
	}
	encrypted := encrypt(raw, group)
	if _, err := io.Copy(file, encrypted); err != nil {
		fmt.Printf("Couldn't write encrypted data into file %v\n%v\n", tmpname, err)
		os.Exit(-1)
	}

	// clean up
	file.Close()
	tmpfile.Close()
	if os.Remove(tmpname) != nil {
		fmt.Printf("Couldn't remove unencrypted temp file %v\nYou should remove it manually.%v\n", tmpname, err)
	}

}

func editSecret(cmd *cobra.Command, args []string) {

	if Verbose {
		fmt.Printf("\nConfiguration:\n")
		fmt.Println("  Using secret keyring:  " + SecRingPath)
		fmt.Println("  Using public keyring:  " + PubRingPath)
		fmt.Println("  Using vault directory: " + VaultDir)
		fmt.Println("  Using editor:          " + Editor)
		fmt.Println()
	}

	if len(args) < 1 {
		fmt.Printf("You must specify a secret to edit\n")
		os.Exit(0)
	}

	secret := bytes.NewBufferString("secret")

	name := args[0]
	spath := filepath.Join(VaultDir, name)
	file, err := os.OpenFile(spath, os.O_RDWR, 0660)

	if err != nil {

		// if there is an error, it is likely because the file doesn't exist
		if os.IsNotExist(err) {
			file, err = os.Create(spath)
			if err != nil {
				fmt.Printf("Couldn't create secret file %v\n%v\n", spath, err)
				os.Exit(-1)
			}
		} else {
			// maybe not
			fmt.Printf("Couldn't open secret file %v\n%v\n", spath, err)
			os.Exit(-1)
		}
	} else {
		// no error opening the existing file, so read the secret
		secret = getSecret(name)
	}
	defer file.Close()

	// Create a temporary file and copy the secret in
	base := ".tmp." + path.Base(spath)
	tmpfile, err := ioutil.TempFile(VaultDir, base)
	if err != nil {
		fmt.Printf("Couldn't create secure temporary file in %v\n%v\n", VaultDir, err)
		os.Exit(-1)
	}
	tmpname := tmpfile.Name()

	if _, err := io.Copy(tmpfile, secret); err != nil {
		fmt.Printf("Couldn't write secret data into temp file %v\n%v\n", tmpname, err)
		os.Exit(-1)
	}
	tmpfile.Close()

	// Run the editor on the temporary file
	c := exec.Command(Editor, tmpname)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	err = c.Run()
	if err != nil {
		fmt.Printf("Couldn't edit temp file %v with editor %v\n%v\n", tmpname, Editor, err)
		os.Exit(-1)
	}

	// Encrypt the temporary file and overwrite the previous secret
	tmpfile, err = os.Open(tmpname)
	if err != nil {
		fmt.Printf("Couldn't read back contents of edited buffer %v\n%v\n", tmpname, err)
		os.Exit(-1)
	}
	raw := new(bytes.Buffer)
	if _, err := raw.ReadFrom(tmpfile); err != nil {
		fmt.Printf("Couldn't read data from %v into buffer\n%v\n", tmpname, err)
		os.Exit(-1)
	}
	encrypted := encrypt(raw, group)
	if _, err := io.Copy(file, encrypted); err != nil {
		fmt.Printf("Couldn't write encrypted data into file %v\n%v\n", tmpname, err)
		os.Exit(-1)
	}

	// clean up
	file.Close()
	tmpfile.Close()
	if os.Remove(tmpname) != nil {
		fmt.Printf("Couldn't remove unencrypted temp file %v\nYou should remove it manually.%v\n", tmpname, err)
	}

}

func encrypt(secret *bytes.Buffer, group string) (out *bytes.Buffer) {

	// open the group file
	groupfile := filepath.Join(VaultDir, group)
	groupKeyring, err := os.Open(groupfile)
	defer groupKeyring.Close()
	if err != nil {
		fmt.Printf("Couldn't open group keyring file %v\n%v\n", groupfile, err)
		os.Exit(-1)
	}

	// Get the group entities
	groupKeys, err := openpgp.ReadArmoredKeyRing(groupKeyring)
	if err != nil {
		fmt.Printf("Couldn't read group keys for %v\n%v\n", group, err)
		os.Exit(-1)
	}

	if Verbose {
		// Print out the list of recipients
		for _, e := range groupKeys {
			fmt.Printf("Encrypting for %016X\n", e.PrimaryKey.KeyId)
		}
	}

	// encrypt
	encrypted := new(bytes.Buffer)
	w, err := openpgp.Encrypt(encrypted, groupKeys, nil, nil, nil)
	if err != nil {
		fmt.Printf("Couldn't encrypt stream\n%v\n", err)
		os.Exit(-1)
	}

	if _, err := secret.WriteTo(w); err != nil {
		fmt.Printf("Couldn't write secret data into encryption buffer\n%v\n", err)
		os.Exit(-1)
	}
	w.Close()

	// armor encoding
	out = new(bytes.Buffer)
	armored, err := armor.Encode(out, "PGP MESSAGE", nil)
	if _, err := io.Copy(armored, encrypted); err != nil {
		fmt.Printf("Couldn't armor data into encryption buffer\n%v\n", err)
		os.Exit(-1)
	}
	armored.Close()

	return

}
