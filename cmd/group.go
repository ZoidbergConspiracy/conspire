package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(groupCmd)
	groupCmd.AddCommand(listCmd)
	groupCmd.AddCommand(addCmd)
	groupCmd.AddCommand(delCmd)
}

// groupCmd represents the group command
var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "conspire group operations",
	Long: `Operations on conspire groups, which include listing members,
adding members, and removing members.`,
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list [group]",
	Short: "list the members of a group",
	Long: `List the members of a key group. If no group is specified, the
default group is used.

Example:

$ conspire list detectives

 Key Id          Key Fingerprint / Identity
--------------- --------------------------------------------------------
4ABEABCDEFCC123B 902123456789070993D2 ABAB4ABEABCDEFCC123B
                 Sherlock Holmes <sherlock.holmes@bakerstreet.co.uk>
4ABEABCDEFCC123C 902123456789070993D2 ABAB4ABEABCDEFCC123C
                 Hercule Poirot <hercule.poirot@whitehaven.co.uk>

`,
	Run: groupList,
}

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add [group] [keyid] ...",
	Short: "add members to a group",
	Long: `Add the listed key ids to the members of a key group.

Example:

$ conspire list add default 4ABEABCDEFCC123B 4ABEABCDEFCC123C
`,
	Run: addList,
}

// delCmd represents the del command
var delCmd = &cobra.Command{
	Use:   "delete [group] [keyid] ...",
	Short: "delete members from a group",
	Long: `Delete the listed key ids from the members of a key group.

Example:

$ conspire list del default 4ABEABCDEFCC123B 4ABEABCDEFCC123C
`,
	Run: delList,
}

func groupList(cmd *cobra.Command, args []string) {

	// The default group is always "default"
	group := "default"

	if len(args) > 0 {
		group = args[0]
	}

	// open the group file
	groupfile, err := os.Open(filepath.Join(VaultDir, group))
	defer groupfile.Close()
	if err != nil {
		fmt.Printf("Couldn't open group file %v\n%v\n", filepath.Join(VaultDir, group), err)
		os.Exit(-1)
	}

	// read the list
	groupList, err := openpgp.ReadArmoredKeyRing(groupfile)
	if err != nil {
		fmt.Printf("Couldn't read members of group file %v\n%v\n", filepath.Join(VaultDir, group), err)
		os.Exit(-1)
	}

	// list available keys
	if Terse {
		// terse give a minimal, parseable format
		for _, e := range groupList {
			fmt.Printf("%016X;%010X:%010X;", e.PrimaryKey.KeyId, e.PrimaryKey.Fingerprint[0:10], e.PrimaryKey.Fingerprint[10:20])

			num := len(e.Identities) - 1
			i := 0
			for label, _ := range e.Identities {
				fmt.Printf("%s", label)
				if i < num {
					fmt.Printf(",")
				}
				i += 1
			}
			fmt.Printf("\n")
		}

	} else {
		// if not terse, print a pretty table

		fmt.Printf("\n")
		fmt.Printf(" Key Id          Key Fingerprint / Identity\n")
		fmt.Printf("---------------- --------------------------------------------------------\n")

		for _, e := range groupList {

			fmt.Printf("%016X %010X %010X\n", e.PrimaryKey.KeyId, e.PrimaryKey.Fingerprint[0:10], e.PrimaryKey.Fingerprint[10:20])

			for label, _ := range e.Identities {
				fmt.Printf("                 %v\n", label)
			}
		}

		fmt.Printf("\n")

	}

}

func addList(cmd *cobra.Command, args []string) {

	if len(args) < 2 {
		fmt.Println("You must specify a group and at least one key to add")
		os.Exit(-1)
	}

	// Open the public keychain for reading
	pubfile, err := os.Open(PubRingPath)
	defer pubfile.Close()
	if err != nil {
		fmt.Printf("Couldn't open public keychain file %v\n%v\n", PubRingPath, err)
		os.Exit(-1)
	}
	pubList, err := openpgp.ReadKeyRing(pubfile)
	if err != nil {
		fmt.Printf("Couldn't read members of public keychain file %v\n%v\n", PubRingPath, err)
		os.Exit(-1)
	}

	groupList := openpgp.EntityList{}

	// read the named list to append to
	group := args[0]
	groupfile, err := os.Open(filepath.Join(VaultDir, group))
	defer groupfile.Close()
	if err != nil {

		if os.IsNotExist(err) {
			if Verbose {
				fmt.Printf("Group file %s doesn't exist. Will create it.\n", group)
			}
		} else {
			fmt.Printf("Couldn't open group file %v\n%v\n", filepath.Join(VaultDir, group), err)
			os.Exit(-1)
		}

	} else {

		groupList, err = openpgp.ReadArmoredKeyRing(groupfile)
		if err != nil {
			fmt.Printf("Couldn't read members of group file %v\n%v\n", filepath.Join(VaultDir, group), err)
			os.Exit(-1)
		}
	}

	// counters
	added := 0
	skipped := 0

	// Start adding
	if Verbose {
		fmt.Printf("Adding users to group %s\n", group)
	}

	for _, keyid := range args[1:] {

		kid, err := hex.DecodeString(keyid)
		if err != nil || len(kid) != 8 {
			if Verbose {
				fmt.Printf("Key %v is not a valid KeyID. Skipping.\n", keyid)
			}
			skipped += 1
			continue
		}

		ukid := binary.BigEndian.Uint64(kid)

		// Is the key already in the group?
		already_there := groupList.KeysById(ukid)
		if len(already_there) > 0 {
			if Verbose {
				fmt.Printf("Key id %X is already in the group. Skipped.\n", ukid)
			}
			skipped += 1
			continue
		}

		// Get key details from the public keychain and add
		match := pubList.KeysById(ukid)
		for _, m := range match {

			for _, id := range m.Entity.Identities {
				if Verbose {
					fmt.Printf("Adding key id %X (%v)\n", ukid, id.Name)
				}
				break
			}
			groupList = append(groupList, m.Entity)
			added += 1
		}

	}

	// explicitly close the files
	pubfile.Close()
	groupfile.Close()

	// re-open the group file for writing
	fout, err := os.Create(filepath.Join(VaultDir, group))
	if err != nil {
		fmt.Printf("Couldn't open %v for writing: %v\n", filepath.Join(VaultDir, group), err)
		os.Exit(-1)
	}

	w, err := armor.Encode(fout, openpgp.PublicKeyType, nil)
	if err != nil {
		fmt.Printf("Couldn't armor %v: %v\n", group, err)
		os.Exit(-1)
	}
	defer w.Close()

	for _, e := range groupList {
		e.Serialize(w)
	}
	fmt.Printf("Added %v and skipped %v\n", added, skipped)

}

func delList(cmd *cobra.Command, args []string) {

	if len(args) < 2 {
		fmt.Println("You must specify a group and at least one key to delete.")
		os.Exit(-1)
	}

	// read the named list to append to
	group := args[0]
	groupfile, err := os.Open(filepath.Join(VaultDir, group))
	defer groupfile.Close()
	if err != nil {

		fmt.Printf("Couldn't open group file %v\n%v\n", filepath.Join(VaultDir, group), err)
		os.Exit(-1)

	}

	groupList, err := openpgp.ReadArmoredKeyRing(groupfile)
	if err != nil {
		fmt.Printf("Couldn't read members of group file %v\n%v\n", filepath.Join(VaultDir, group), err)
		os.Exit(-1)
	}

	// counters
	deleted := 0
	skipped := 0

	// Start deleting
	if Verbose {
		fmt.Printf("Deleting users from group %s\n", group)
	}

	for _, keyid := range args[1:] {

		kid, err := hex.DecodeString(keyid)
		if err != nil || len(kid) != 8 {
			if Verbose {
				fmt.Printf("Key %v is not a valid KeyID. Skipping.\n", keyid)
			}
			skipped += 1
			continue
		}

		ukid := binary.BigEndian.Uint64(kid)
		found := false

		// Is the key already in the group?
		for _, e := range groupList {

			if e.PrimaryKey == nil {
				continue
			}

			if ukid == e.PrimaryKey.KeyId {
				found = true
				e.PrimaryKey = nil
				deleted += 1
				if Verbose {
					fmt.Printf("Key id %X deleted\n", ukid)
				}

			}

		}

		if found == false {
			if Verbose {
				fmt.Printf("Key id %X not found. Skipped.\n", ukid)
			}
			skipped += 1
		}

	}

	// explicitly close the files
	groupfile.Close()

	// re-open the group file for writing
	fout, err := os.Create(filepath.Join(VaultDir, group))
	if err != nil {
		fmt.Printf("Couldn't open %v for writing: %v\n", filepath.Join(VaultDir, group), err)
		os.Exit(-1)
	}

	w, err := armor.Encode(fout, openpgp.PublicKeyType, nil)
	if err != nil {
		fmt.Printf("Couldn't armor %v: %v\n", group, err)
		os.Exit(-1)
	}
	defer w.Close()

	for _, e := range groupList {
		if e.PrimaryKey != nil {
			e.Serialize(w)
		}
	}
	fmt.Printf("Deleted %v and skipped %v\n", deleted, skipped)

}
