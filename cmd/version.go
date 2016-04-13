package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionInfo = "conspire version 0.1.0 (c) 2016 Thornton Prime"

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show the current version",
	Long: `Show the current version and other information about the current
conspiracy environment.`,
	Run: showVersion,
}

func showVersion(cmd *cobra.Command, args []string) {

	fmt.Println(versionInfo)

	if Verbose {
		fmt.Printf("\nConfiguration:\n")
		fmt.Println("  Using secret keyring:  " + SecRingPath)
		fmt.Println("  Using public keyring:  " + PubRingPath)
		fmt.Println("  Using vault directory: " + VaultDir)
	}
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
