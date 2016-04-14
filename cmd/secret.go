package cmd

import (
	"github.com/spf13/cobra"
)

// secretCmd represents the secret command
var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "perform an operation on a secret",
	Long:  `Operate on a secret within the conspiracy.`,
}

func init() {
	RootCmd.AddCommand(secretCmd)
}
