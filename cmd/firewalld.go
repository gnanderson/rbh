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
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gnanderson/xrpl"
	"github.com/godbus/dbus"
)

// https://firewalld.org/documentation/man-pages/firewalld.dbus.html
const (
	fwdObjPath     = "/org/fedoraproject/FirewallD1"
	fwdInterface   = "org.fedoraproject.FirewallD1"
	alreadyEnabled = "ALREADY_ENABLED"
)

const (
	protoTCP = "tcp"
)

var (
	dbusConn *dbus.Conn
	dbusObj  dbus.BusObject
	fwdUp    bool
	defZone  string

	errAlreadyEnabled = errors.New(alreadyEnabled)
)

type rejectRule struct {
	family  string
	source  net.IP
	timeout int
}

// This is a simple reject rich rule definition based on the source ip. The
// rule when printed in it's string format is not permanent because it is
// intented to be used with the firewalld rich rule timeout option.
func newRejectRule(ip string, timeout int) (*rejectRule, error) {
	IP := net.ParseIP(ip)
	if IP == nil {
		return nil, fmt.Errorf("firewalld: invalid IP address '%s'", IP)
	}

	return &rejectRule{family: "ipv4", source: IP, timeout: timeout}, nil
}

func (rr *rejectRule) String() string {
	return fmt.Sprintf(
		"rule family='%s' source address='%s' reject",
		rr.family,
		rr.source.String(),
	)
}

// Query DBUS to see if we can retreive the firewalld default zone and therefor
// understand if firewalld is up
func fwdCheck() (err error) {
	if dbusConn, err = dbus.SystemBus(); err != nil {
		fwdUp = false
		return err
	}

	dbusObj = dbusConn.Object(fwdInterface, dbus.ObjectPath(fwdObjPath))

	if err = dbusObj.Call(fwdInterface+".getDefaultZone", 0).Store(&defZone); err != nil {
		dbusConn.Close()
		return err
	}
	log.Println("firewall: zone - ", defZone)
	fwdUp = true

	return nil
}

// If the service tries to add an existing rich rule specify this error so we
// can ignore and take no action.
func toKnownErr(err error) error {
	if err == nil {
		return err
	}

	switch {
	case strings.HasPrefix(err.Error(), alreadyEnabled):
		return errAlreadyEnabled
	}

	return err
}

// Notify on a channel if firewalld is reloaded by sysadmin/ops, we'll want to
// know about this so we can re-apply any bans in the blacklist that have not
// expired
func notifyReload(notify chan<- *dbus.Signal) {
	if dbusConn == nil {
		return
	}
	dbusConn.BusObject().(*dbus.Object).AddMatchSignal(fwdInterface, "Reloaded")
	dbusConn.Signal(notify)
}

type blEntry struct {
	peer    xrpl.Peer
	expires time.Time
}

func (ble *blEntry) expired() bool {
	return ble.expires.Sub(time.Now()) >= 0
}

type blacklist struct {
	entries  map[string]*blEntry
	duration time.Duration
}

func (bl *blacklist) add(peer xrpl.Peer) {
	newEntry := &blEntry{
		peer:    peer,
		expires: time.Now().Add(bl.duration),
	}

	if _, ok := bl.entries[peer.PublicKey]; !ok {
		bl.entries[peer.PublicKey] = newEntry
	}
}

func (bl *blacklist) expireEntries() {
	for _, entry := range bl.entries {
		if entry.expired() {
			delete(bl.entries, entry.peer.PublicKey)
		}
	}
}

type whitelist struct {
	entries map[string]xrpl.Peer
}

func (wl *whitelist) containrs(peer xrpl.Peer) bool {
	if _, ok := wl.entries[peer.PublicKey]; ok {
		return true
	}
	return false
}

type firewall struct {
	whitelist *whitelist
	blacklist *blacklist
}

func newFirewall() *firewall {
	return &firewall{
		whitelist: &whitelist{entries: make(map[string]xrpl.Peer, 0)},
		blacklist: &blacklist{
			entries:  make(map[string]*blEntry),
			duration: time.Duration(banLength) * time.Minute,
		},
	}
}

// Ban the peer by inserting the reject rule, add it to a blacklist so we
// can track the expiration and re-apply on firewalld reload
func (fw *firewall) banPeer(peer xrpl.Peer) {
	reject, err := newRejectRule(peer.IP().String(), 10)
	if err != nil {
		log.Println(err)
		return
	}

	err = fw.addReject("public", reject.String(), int(fw.blacklist.duration.Seconds()))
	if err != errAlreadyEnabled && err != nil {
		log.Println(err)
	}

	fw.blacklist.add(peer)
}

// Insert the reject rich rule
func (fw *firewall) addReject(zone, rule string, timeout int) error {
	if zone == "" {
		zone = defZone
	}

	if dbusObj == nil || !fwdUp {
		return errors.New("firewalld: not running")
	}

	log.Println(fmt.Sprintf("firewalld: adding rule (%s) to %s zone", rule, zone))

	return toKnownErr(dbusObj.Call(
		fwdInterface+".zone.addRichRule",
		0,
		zone,
		rule,
		timeout,
	).Store(&zone))
}

// add a port in a zone - currently unused but included for future functionality
func addPort(zone string, port, timeout int) error {
	if zone == "" {
		zone = defZone
	}

	if port <= 0 {
		return fmt.Errorf("firewalld: invalid port '%d'", port)
	}

	if dbusObj == nil || !fwdUp {
		return errors.New("firewalld: not running")
	}

	log.Println(fmt.Sprintf("firewalld: adding port '%d' added to %s zone", port, zone))

	return dbusObj.Call(
		fwdInterface+".zone.addPort",
		0,
		zone,
		strconv.Itoa(port),
		protoTCP,
		timeout,
	).Store(&zone)
}

// remove a port in a zone - currently unused but included for future functionality
func removePort(zone string, port, timeout int) error {
	if zone == "" {
		zone = defZone
	}

	if port <= 0 {
		return fmt.Errorf("firewalld: invalid port '%d'", port)
	}

	if dbusObj == nil || !fwdUp {
		return errors.New("firewalld: not running")
	}

	log.Println(fmt.Sprintf("firewalld: removing port '%d' from %s zone", port, zone))

	return dbusObj.Call(
		fwdInterface+".zone.removePort",
		0,
		zone,
		strconv.Itoa(port),
		protoTCP,
		timeout,
	).Store(&zone)
}
