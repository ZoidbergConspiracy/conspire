// Copyright © 2016 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	//"github.com/spf13/viper"
)

// This represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "conspire",
	Short: "A tool for managing encrypted secrets among groups",
	Long: versionInfo + `

Conspire is a tool for managing encrypted secrets among groups. It uses
OpenGPG keys to encrypt secrets for multiple people. It also includes
support for managing groups of users as distinct keychains.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//Run: CmdRun,
}

var SecRingPath = ""
var PubRingPath = ""
var VaultDir = ""
var Terse = false
var Verbose = false

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().BoolVarP(&Terse, "terse", "t", false, "terse (machine-parseable) output")
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {

	gpghome := os.Getenv("GNUPGHOME")
	if gpghome == "" {
		gpghome = filepath.Join(os.Getenv("HOME"), ".gnupg")
	}
	SecRingPath = filepath.Join(gpghome, "secring.gpg")
	PubRingPath = filepath.Join(gpghome, "pubring.gpg")

	VaultDir = os.Getenv("CONSPIRACY_VAULT")
	if VaultDir == "" {
		VaultDir, _ = os.Getwd()
	}

}
