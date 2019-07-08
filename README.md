# rbh - rippled ban hammer

Follow me on Twitter - [@diakritikal](https://twitter.com/diakritikal)

1. [Credit](#credit)
1. [Status](#status)
1. [Requirements](#requirements)
1. [Installation](#installation)
1. [Usage](#usage)
1. [Configuration](#configuration)
1. [Rational](#rational)

## Credit
This tool is inspired by Rabbit's rippled ban hammer python script:
  https://github.com/crypticrabbit/rippled-ban-hammer

Many thanks to Rabbit, Alloy Networks and Nik Bougalis in providing valuable
advice for operating XRPL nodes. Follow them on Twitter!

  - [@RabbitKickClub](https://twitter.com/RabbitKickClub)
  - [@alloynetworks](https://twitter.com/alloynetworks)
  - [@nbougalis](https://twitter.com/nbougalis)

## Status

### WARNING
This tool is not currently fit for production use, use at your own risk.

TODO:
  - [✔] race check data structures accessed concurrently
  - [ ] whitelist support
  - [✔] config via file and env vars
  - [ ] add to CI
  - [ ] provide container/docker release
  - [✔] release management
  - [ ] socket closing mechanism for banned peers
  - [ ] correclty support ipv6

## Requirements

### Ban Functionality

The ban functionality is built on [firewalld](https://firewalld.org/). It is
unlikely systems without `firewalld` will be supported. This is purely because
as far as I'm aware the alternatives e.g. Ubuntu `ufw` don't have any convenient
communication layer (D-BUS) exposed to program against. You can of course
configure your Debian/Ubuntu system to use `firewalld`. There are official
packages available.

Off the top of my head I think this should work on the following Linux flavours.

  - SLES 15+
  - RHEL 7+
  - CentOS 7+
  - OpenSUSE Leap
  - Fedora Core 21+ - I hope you have upgraded ;)
  - Arch

## Socket Closing Functionality

To be developed/discussed - `ss -K [filter]` will probably be the first method
supported with `tcpkill` *maybe* added later. This functionality will likely need
Kernel 4.9+ and compiled with `CONFIG_INET_DIAG_DESTROY`.

## Installation

Currently you'll need to install with `go get github.com/gnanderson/rbh`. Better
release management is planned.

## Usage

 -  `rbh help`
 -  `rbh help run`
 -  `rbh help show`

## Configuration

Outside of flag usage you have the following configuration strategies available.
Keys for both config strategies correspond to the flags you can discover from
the help commands above.

 - yaml config, [example](https://github.com/gnanderson/rbh/blob/master/examples/.rbh.yaml)
 - env vars, env var keys are prefixed with `RBH_` e.g. `RBH_ADDR`

## Rational

Rabbit's ban hammer script has been very helpful in helping stabilise my XRPL
nodes. However, it performs direct modification of the servers `iptables` chains
and since my servers utilise `firewalld` I didn't want to have conflicts or
even have `iptables` lose the drop/reject entries. This might happen for example
on a `firewalld` reload or modification of the zones.

A lesser concern was the Kernel developers plans to move away from `iptables`
towards using `bpfilter`. That's probably some way off but `firewalld` would
continue to act as the frontend when this happens so there's an amount of future
proofing by leveraging `firewalld`

`firewalld` exposes it's functionality on the Kernel's D-BUS IPC layer, this is
perfect for programatically integrating with Kernel netfiltering.

  - [firewalld D-BUS](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)

So I endeavoured to investigate this approach and base this tool around direct
`firewalld` integration through D-BUS.
