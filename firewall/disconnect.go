package firewall

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gnanderson/xrpl"
)

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

// Disconnector is an interface accepted by the firewall to disconnect a peers
// socket after banning it
type Disconnector interface {
	Disconnect(peer *xrpl.Peer) error
}

// SSDisconnector uses the ss utility from the iproute2 suite of packages. The
// option used is `ss -K [filter]` where filter identifies the IP address of the
// peer. Here is the description from the man page.
//
//   -K, --kill
//       Attempts to forcibly close sockets. This option displays sockets that
//       are successfully closed and silently skips sockets that the kernel does
//       not support closing. It supports IPv5 and IPv6 sockets only.
//
// Please note that Linux kernel 4.9 or higher is required with `CONFIG_INET_DIAG_DESTROY`
// option compiled in. On systems where the kernel doesn't support this, the operation
// will silently fail.
//
// This Disconnector will execute a command similar to the following
//    `ss -K dst 192.168.1.10`
//
// Needless to say, this requires root or elevated privileges.
type SSDisconnector struct {
	Docker    bool
	Container string
}

// NewSSDisconnector returns a Disconnector configured to use `ss -K`
func NewSSDisconnector(container string) *SSDisconnector {
	return &SSDisconnector{Docker: container != "", Container: container}
}

// DefaultDisconnector used to close sockets
var DefaultDisconnector = &SSDisconnector{}

// Disconnect will try to close the peer's socket
func (ssd *SSDisconnector) Disconnect(peer *xrpl.Peer) error {
	var out bytes.Buffer
	var cmdStr = "ss"
	var args = []string{"-K", "-H", fmt.Sprintf("dst %s", peer.IP().String())}

	if ssd.Docker {
		cmdStr = "docker"
		args = append([]string{"exec", ssd.Container, "ss"}, args...)
	}

	cmd := exec.Command(cmdStr, args...)
	cmd.Stdout = &out
	err := cmd.Run()

	logMsg := out.String()
	logMsg = strings.TrimSuffix(logMsg, "\n")
	if strings.TrimSpace(logMsg) == "" {
		logMsg = "Peer not disconnected or `ss -K` unsupported"
	}

	log.Println("firewall disconnect:", logMsg)

	return err
}

// TCPKillDisconnector requires the `tcpkill` utility to be available on the
// system. This utility is more of a brute force approach and may not work
// consitently - especially on nodes with many open connections and very high
// trafic volume.
//
// `tcpkill` tries to close the connection by sniffing for the IP's traffic
// and then agressively trying to inject a RST packet into the TCP stack
// receive window. For this reason it may not be successful, but you can try
// more agressive levels than the default (3), levels are 1-9.
type TCPKillDisconnector struct {
	Agression int
	iface     string
	Docker    bool
	Container string
}

// NewTCPKIllDisconnector returns a Disconnector configured to use `tcpkill`
func NewTCPKIllDisconnector(container string) *TCPKillDisconnector {
	return &TCPKillDisconnector{Agression: 3, Docker: container != "", Container: container}
}

// Disconnect will try to close the peer's socket
func (tcp *TCPKillDisconnector) Disconnect(peer *xrpl.Peer) error {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	var cmdStr = "tcpkill"
	var args = []string{"-i", tcp.iface, strconv.Itoa(tcp.Agression)}

	if tcp.Docker {
		cmdStr = "docker"
		args = append([]string{"exec", tcp.Container, "tcpkill"}, args...)
	}

	cmd := exec.CommandContext(ctx, cmdStr, args...)
	cmd.Stdout = &out

	timeout := time.After(500 * time.Millisecond)
	errCh := make(chan error)

	go func() {
		err := cmd.Run()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		cancel()
		return err
	case <-timeout:
		cancel()
		log.Println(out)
	}

	return nil
}
