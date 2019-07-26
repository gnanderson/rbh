package cmd

/*
Copyright © 2019 Graham Anderson <graham@grahamanderson.scot>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	cfgFile, nodeAddr, nodePort, adminUser, adminPassword, minVersion string
	useTls                                                            bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rbh",
	Short: "rbh gives errant XRPL (rippled) nodes \"Ye Olde Ban Hammer\"",
}

// NewCommand returns the roo cmd
func NewCommand() *cobra.Command {
	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.rbh.yaml)")
	rootCmd.PersistentFlags().StringVarP(&nodeAddr, "addr", "a", "127.0.0.1", "admin websocket RPC service address")
	rootCmd.PersistentFlags().StringVarP(&nodePort, "port", "p", "6006", "admin websocket RPC service port")
	rootCmd.PersistentFlags().StringVar(&adminUser, "user", "", "admin_user if any configured in rippled config")
	rootCmd.PersistentFlags().StringVar(&adminPassword, "passwd", "", "admin_password if any configured in rippled config")
	rootCmd.PersistentFlags().BoolVarP(&useTls, "tls", "t", false, "use wss scheme, omitting this flag assumes running on localhost")
	rootCmd.PersistentFlags().StringVarP(&minVersion, "minver", "m", "1.2.4", "Minimum version number acceptable to avoid the ban hammer.")
	viper.BindPFlag("addr", rootCmd.PersistentFlags().Lookup("addr"))
	viper.BindPFlag("port", rootCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("user", rootCmd.PersistentFlags().Lookup("user"))
	viper.BindPFlag("passwd", rootCmd.PersistentFlags().Lookup("passwd"))
	viper.BindPFlag("tls", rootCmd.PersistentFlags().Lookup("tls"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".rbh" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".rbh")
	}

	viper.SetEnvPrefix("RBH")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
