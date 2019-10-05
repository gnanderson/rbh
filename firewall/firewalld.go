package firewall

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
	"sync"
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
// intended to be used with the firewalld rich rule timeout option.
func newRejectRule(ip string, timeout int) (*rejectRule, error) {
	IP := net.ParseIP(ip)
	if IP == nil {
		return nil, fmt.Errorf("firewalld: invalid IP address '%s'", IP)
	}

	family := "ipv4"
	if IP.To4() == nil {
		family = "ipv6"
	}

	return &rejectRule{family: family, source: IP, timeout: timeout}, nil
}

func (rr *rejectRule) String() string {
	return fmt.Sprintf(
		"rule family='%s' source address='%s/32' reject",
		rr.family,
		rr.source.String(),
	)
}

type dropRule struct {
	family  string
	source  net.IP
	timeout int
}

func newDropRule(ip string, timeout int) (*dropRule, error) {
	IP := net.ParseIP(ip)
	if IP == nil {
		return nil, fmt.Errorf("firewalld: invalid IP address '%s'", IP)
	}

	family := "ipv4"
	if IP.To4() == nil {
		family = "ipv6"
	}

	return &dropRule{family: family, source: IP, timeout: timeout}, nil
}

func (dr *dropRule) String() string {
	return fmt.Sprintf(
		"rule family='%s' source address='%s/32' drop",
		dr.family,
		dr.source.String(),
	)
}

// Connect queries DBUS to see if we can retrieve the firewalld default zone and
// therefor understand if firewalld is up
func Connect() (err error) {
	if dbusConn, err = dbus.SystemBus(); err != nil {
		log.Println("dbus:", err)
		fwdUp = false
		return err
	}

	dbusObj = dbusConn.Object(fwdInterface, dbus.ObjectPath(fwdObjPath))

	if err = dbusObj.Call(fwdInterface+".getDefaultZone", 0).Store(&defZone); err != nil {
		log.Println("firewalld: cannot retrieve zone, check user permission or firewalld status", err)
		dbusConn.Close()
		return err
	}
	log.Println("firewall: zone - ", defZone)
	fwdUp = true

	return nil
}

// Up returns true if firewalld is available to use
func Up() bool {
	return fwdUp
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

// NotifyReload on a channel if firewalld is reloaded by sysadmin/ops, we'll want to
// know about this so we can re-apply any bans in the blacklist that have not
// expired
func NotifyReload(notify chan<- *dbus.Signal) {
	if dbusConn == nil {
		panic("firewall not available")
	}
	dbusConn.BusObject().(*dbus.Object).AddMatchSignal(fwdInterface, "Reloaded")
	dbusConn.Signal(notify)
}

type blEntry struct {
	peer    *xrpl.Peer
	expires time.Time
}

func (ble *blEntry) expired() bool {
	return ble.expires.Sub(time.Now()) < 0
}

type blacklist struct {
	sync.Mutex
	entries  map[string]*blEntry
	duration time.Duration
}

func (bl *blacklist) add(peer *xrpl.Peer) {
	bl.Lock()
	defer bl.Unlock()

	newEntry := &blEntry{
		peer:    peer,
		expires: time.Now().Add(bl.duration),
	}

	if _, ok := bl.entries[peer.PublicKey]; !ok {
		bl.entries[peer.PublicKey] = newEntry
	}
}

func (bl *blacklist) contains(peer *xrpl.Peer) bool {
	bl.Lock()
	defer bl.Unlock()

	if _, ok := bl.entries[peer.PublicKey]; ok {
		return true
	}
	return false
}

func (bl *blacklist) expireEntries() {
	bl.Lock()
	defer bl.Unlock()

	for _, entry := range bl.entries {
		if entry.expired() {
			delete(bl.entries, entry.peer.PublicKey)
		}
	}
}

type whitelist struct {
	entries map[string]*xrpl.Peer
}

func (wl *whitelist) add(ip string) {
	if _, ok := wl.entries[ip]; !ok {
		wl.entries[ip] = nil
	}
}

func (wl *whitelist) contains(peer *xrpl.Peer) bool {
	if _, ok := wl.entries[peer.IP().String()]; ok {
		// always update the peer data with current known state
		wl.entries[peer.IP().String()] = peer
		return true
	}
	return false
}

// Firewall is a wrapper round `firewalld` that provides functionality for
// temporarily banning XRPL peer nodes
type Firewall struct {
	Disconnector Disconnector
	whitelist    *whitelist
	blacklist    *blacklist
}

// NewFirewall instantiates a Firewall ready for use with XRPL peer nodes
func NewFirewall(banLength int, whiteList ...string) *Firewall {
	fw := &Firewall{
		Disconnector: DefaultDisconnector,
		whitelist:    &whitelist{entries: make(map[string]*xrpl.Peer)},
		blacklist: &blacklist{
			entries:  make(map[string]*blEntry),
			duration: time.Duration(banLength) * time.Minute,
		},
	}

	for _, entry := range whiteList {
		fw.whitelist.add(entry)
	}

	return fw
}

// BanPeer bans the XRPL peer by inserting the reject rule, and adds it to a
// blacklist so we can track the expiration and re-apply on firewalld reload.
// IP's that are in the whitelist are ignored...
func (fw *Firewall) BanPeer(peer *xrpl.Peer) {
	if fw.whitelist.contains(peer) {
		return
	}

	drop, err := newDropRule(
		peer.IP().String(),
		int(fw.blacklist.duration.Seconds()),
	)

	if err != nil {
		log.Println(err)
		return
	}

	err = fw.addReject("drop", drop.String(), int(fw.blacklist.duration.Seconds()))
	if err != errAlreadyEnabled && err != nil {
		log.Println(err)
	}

	fw.blacklist.add(peer)

	fw.Disconnect(peer)
}

// Expire will traverse the blacklist and remove any XRPL peers which have
// exceeded their ban length
func (fw *Firewall) Expire() {
	fw.blacklist.expireEntries()
}

// RefreshBans re-applies the rich rule banning unstable peers, this is used
// after the firewall reload notify signal.
func (fw *Firewall) RefreshBans() {
	fw.Expire()
	for _, entry := range fw.blacklist.entries {
		reject, err := newRejectRule(
			entry.peer.IP().String(),
			int(entry.expires.Sub(time.Now()).Seconds()),
		)
		if err != nil {
			log.Println(err)
			continue
		}

		err = fw.addReject(
			"public",
			reject.String(),
			int(fw.blacklist.duration.Seconds()),
		)
		if err != errAlreadyEnabled && err != nil {
			log.Println(err)
		}
	}
}

// Disconnect a peer socket
func (fw *Firewall) Disconnect(peer *xrpl.Peer) {
	if err := fw.Disconnector.Disconnect(peer); err != nil {
		log.Println("firewall disconnect:", err)
	}
}

// Insert the reject rich rule
func (fw *Firewall) addReject(zone, rule string, timeout int) error {
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
