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
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/gnanderson/xrpl"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	. "github.com/logrusorgru/aurora"
)

const (
	argPeers      = "peers"
	argStable     = "stable"
	argUnstable   = "unstable"
	argCandidates = "candidates"
)

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show <arg> [flags]",
	Short: "show blacklist and peers",
	Args:  cobra.MinimumNArgs(1),
	Long: `Valid args:

  candidates: show peers matching blacklist criteria
  peers: show all connected peers
  stable: show all stable peers
  unstable show current unstable peers`,
	Run: func(cmd *cobra.Command, args []string) {
		show(args)
	},
}

var anonymise bool

func init() {
	rootCmd.AddCommand(showCmd)
	showCmd.Flags().BoolVarP(&anonymise, "anonymise", "x", false, "Anonymise the peers IP for testing/ci purposes")
}

func show(args []string) {
	n := xrpl.NewNode(viper.GetString("addr"), viper.GetString("port"), viper.GetBool("useTls"))
	arg := args[0]
	if (arg != argPeers) && (arg != argStable) && (arg != argUnstable) && (arg != argCandidates) {
		log.Println("invalid argument")
		return
	}

	cmd := xrpl.NewPeerCommand()
	cmd.AdminUser = viper.GetString("user")
	cmd.AdminPassword = viper.GetString("passwd")
	xrpl.MinVersion = semver.Must(semver.NewVersion(minVersion))

	msg := n.DoCommand(cmd)
	if msg == nil {
		log.Println("no response")
	}

	pl, err := xrpl.UnmarshalPeers(string(msg.Msg))
	if err != nil {
		log.Fatal(err)
	}

	var peers []*xrpl.Peer

	switch arg {
	case argCandidates:
		fallthrough
	case argPeers:
		peers = pl.Peers()
	case argStable:
		peers = pl.Stable()
	case argUnstable:
		peers = pl.Unstable()
	}

	if anonymise {
		pl.Anonymise()
		return
	}

	lineFromPeer := func(peer *xrpl.Peer) []string {
		uptime := time.Second * time.Duration(peer.Uptime)
		switch peer.Sanity {
		case xrpl.Insane:
			peer.Sanity = Red(peer.Sanity).String()
		case xrpl.Unstable:
			peer.Sanity = Yellow(peer.Sanity).String()
		case xrpl.Good:
			peer.Sanity = Green(peer.Sanity).String()
		case xrpl.Old:
			peer.Sanity = Cyan(peer.Sanity).String()
		}
		return []string{
			peer.IP().String(),
			peer.Sanity,
			peer.Version,
			uptime.String(),
			strconv.Itoa(peer.Latency),
			strconv.Itoa(peer.Load),
			peer.PublicKey,
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"IP", "Status", "Version", "Uptime", "Latency", "Load", "Public Key"})

	for _, peer := range peers {
		if peer.TooOld() {
			peer.Sanity = xrpl.Old
		}
		if peer.Sanity == "" {
			peer.Sanity = xrpl.Good
		}
		line := lineFromPeer(peer)

		if arg == argCandidates {
			if !peer.StableWith(xrpl.DefaultStabilityChecker) {
				line := lineFromPeer(peer)
				table.Append(line)
			}
			continue
		}
		table.Append(line)

	}

	table.SetFooter([]string{"PEER COUNT", strconv.Itoa(table.NumLines()), "", "", "", "", ""})
	table.SetBorder(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()
}
