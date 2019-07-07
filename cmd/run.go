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
	"context"
	"log"
	"time"

	"github.com/gnanderson/rbh/firewall"
	"github.com/gnanderson/xrpl"
	"github.com/godbus/dbus"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run the automatic ban hammer",
	Long: `run command will run as a service connecting to the XRPL node specifid.

Periodically this service will query the XRPL node for a list of peers and decide
whether to swing the ban hammer.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Fatal(run())
	},
}

var (
	printTable           bool
	banLength, repeatCmd int
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().IntVarP(&banLength, "banlength", "b", 1440, "the duration of the ban (in minutes) for unstable peers")
	runCmd.Flags().IntVarP(&repeatCmd, "repeat", "r", 60, "check for new peers to ban after 'repeat' seconds")
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	n := xrpl.NewNode(nodeAddr, nodePort, useTls)
	fw := firewall.NewFirewall(banLength)

	expireBlacklist(ctx, fw)

	cmd := xrpl.NewPeerCommand()
	cmd.AdminUser = "graham"
	cmd.AdminPassword = "testnet"

	if err := firewall.Connect(); err != nil {
		log.Fatal(err)
	}
	refreshBans(ctx, fw)

	for msg := range n.RepeatCommand(
		ctx,
		cmd,
		repeatCmd,
	) {
		if msg.Err != nil {
			cancel()
			return msg.Err
		}

		pl, err := xrpl.UnmarshalPeers(string(msg.Msg))
		if err != nil {
			cancel()
			return err
		}

		for _, peer := range pl.Unstable() {
			if !peer.StableWith(xrpl.DefaultStabilityChecker) {
				if firewall.Up() {
					fw.BanPeer(peer)
				}
			}
		}
	}

	log.Println("Message channel closed")
	cancel()

	return nil
}

func refreshBans(ctx context.Context, fwl *firewall.Firewall) {
	notify := make(chan *dbus.Signal)
	firewall.NotifyReload(notify)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-notify:
				log.Println("firewalld reloaded")
				fwl.RefreshBans()
			}
		}
	}()
}

func expireBlacklist(ctx context.Context, firewall *firewall.Firewall) {
	ticker := time.NewTicker(time.Second * 60)

	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				log.Println("flushing expires entries")
				firewall.Expire()
			}
		}
	}()
}
