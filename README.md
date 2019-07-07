# rbh - rippled ban hammer

1. [Credit](#credit)
1. [Status](#status)
1. [Installation](#installation)
1. [Usage](#usage)
1. [Rational](#rational)

## Credit
This tool is inspired by Rabbit's rippled ban hammer python script:
  https://github.com/crypticrabbit/rippled-ban-hammer

Many thanks to Rabit Alloy Networks and Nik Bougalis in providing valuable
advice for operating XRPL nodes. Follow them on Twitter!

  - @RabbitKickClub
  - @alloynetworks
  - @nbougalis

## Status

### WARNING
This tool is not currently fit for production use, use at your own risk.

TODO:
  [] config via file and env vars
  [] add to CI
  [] provide container/docker release
  [] release management
  [] socket closing mechanism for banned peers

## Installation

Currently you'll need to install with `go get github.com/gnanderson/rbh`. Better
release management is planned.

## Usage

  `rbh help`
  `rbh help run`
  `rbh help show`

## Rational

Rabbit's ban hammer script has been very helpful in helping stabilise my XRPL
nodes. However, it performs direct modification of the servers `iptables` chains
and since my servers utilise `firewalld` I didn't want to have conflicts or
even have `iptables` lose the drop/reject entries. This might happen for example
on a `firewalld` reload or modification of the zones.

A lesser concern was the Kernel developers plans to move away from `iptables`
towards using `bpfilter`. That's probably some way off but `firewalld` would
continue to act as the frontend when this happens to there's an amount of future
proofing by leveraging `firewalld`

`firewalld` exposes it's functionality on the Kernel's D-BUS IPC layer, this is
perfect for programatically integrating with Kernel netfiltering.

So I endeavoured to investigate this approach and base this tool around direct
`firewalld` integration through D-BUS.


