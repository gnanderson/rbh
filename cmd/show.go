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
	"log"
	"os"
	"strconv"

	"github.com/gnanderson/xrpl"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

const (
	argPeers    = "peers"
	argStable   = "stable"
	argUnstable = "unstable"
)

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show <arg> [flags]",
	Short: "show blacklist and peers",
	Args:  cobra.MinimumNArgs(1),
	Long: `Valid args:

  peers: show all connected peers
  stable: show all stable peers
  unstable show current unstable peers`,
	Run: func(cmd *cobra.Command, args []string) {
		show(args)
	},
}

func init() {
	rootCmd.AddCommand(showCmd)
}

func show(args []string) {
	n := xrpl.NewNode(nodeAddr)
	arg := args[0]
	if (arg != argPeers) && (arg != argStable) && (arg != argUnstable) {
		log.Println("invalid argument")
		return
	}

	cmd := xrpl.NewPeerCommand()
	cmd.AdminUser = "graham"
	cmd.AdminPassword = "testnet"

	msg := n.DoCommand(cmd)
	if msg == nil {
		log.Println("no response")
	}

	pl, err := xrpl.UnmarshalPeers(string(msg.Msg))
	if err != nil {
		log.Println(err)
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"IP", "Version", "Sanity", "Uptime", "Public Key"})

	var peers []xrpl.Peer

	switch arg {
	case argPeers:
		peers = pl.Peers()
	case argStable:
		peers = pl.Stable()
	case argUnstable:
		peers = pl.Unstable()
	}

	for _, peer := range peers {
		if peer.Sanity == "" {
			peer.Sanity = "good"
		}
		line := []string{
			peer.IP().String(),
			peer.Version,
			peer.Sanity,
			strconv.Itoa(peer.Uptime), peer.PublicKey,
		}
		if arg == argUnstable {
			if !peer.StableWith(xrpl.DefaultStabilityChecker) {
				table.Append(line)
			}
			continue
		}

		table.Append(line)

	}
	table.SetBorder(false)
	table.Render()

}
