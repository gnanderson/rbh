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
	"net"

	"github.com/gnanderson/rbh/firewall"
	"github.com/gnanderson/xrpl"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// banCmd represents the ban command
var banCmd = &cobra.Command{
	Use:   "ban",
	Short: "ban one or more IP addresses",
	Args:  cobra.MinimumNArgs(1),
	Long:  `Ban one of more IP address provided as a space separated list of args`,
	Run: func(cmd *cobra.Command, args []string) {
		ban(args)
	},
}

func init() {
	rootCmd.AddCommand(banCmd)
	banCmd.Flags().IntVarP(&banLength, "banlength", "b", 1440, "the duration of the ban (in minutes)")
	banCmd.Flags().StringVarP(&container, "docker", "d", "", "Optional name of a docker container to exec the socket close on.")
	banCmd.Flags().BoolVarP(&tcpkill, "tcpkill", "k", false, "Use `tcpkill` instead of `ss -K` to close the banned peers socket.")
}

func ban(args []string) {
	ips := make([]net.IP, 0)
	for _, ip := range args {
		netIP := net.ParseIP(ip)
		if netIP == nil {
			log.Printf("invalid IP %s", ip)
			continue
		}
		ips = append(ips, netIP)
	}

	if len(ips) == 0 {
		log.Fatal("no valid ips provided")
	}

	n := xrpl.NewNode(viper.GetString("addr"), viper.GetString("port"), viper.GetBool("useTls"))

	cmd := xrpl.NewPeerCommand()
	cmd.AdminUser = viper.GetString("user")
	cmd.AdminPassword = viper.GetString("passwd")

	if err := firewall.Connect(); err != nil {
		log.Fatal("Exiting...", err)
	}

	msg := n.DoCommand(cmd)
	if msg == nil {
		log.Println("no response")
	}

	pl, err := xrpl.UnmarshalPeers(string(msg.Msg))
	if err != nil {
		log.Fatal(err)
	}
	fw := firewall.NewFirewall(banLength, viper.GetStringSlice("whitelist")...)
	if container != "" {
		fw.Disconnector = firewall.NewSSDisconnector(viper.GetString("docker"))
	}
	if tcpkill {
		fw.Disconnector = firewall.NewTCPKIllDisconnector(viper.GetString("docker"))
	}

	for _, peer := range pl.Peers() {
		for _, ip := range ips {
			if ip.Equal(peer.IP()) {
				fw.BanPeer(peer)
				log.Println("peer banned:", peer.IP().String(), peer.PublicKey)
			}
		}
	}
}
