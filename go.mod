module github.com/gnanderson/rbh

go 1.13

require (
	github.com/coreos/go-semver v0.3.0
	github.com/gnanderson/xrpl v0.0.11
	github.com/godbus/dbus v5.0.1+incompatible
	github.com/gorilla/websocket v1.4.0
	github.com/logrusorgru/aurora v0.0.0-20190428105938-cea283e61946
	github.com/mattn/go-runewidth v0.0.4 // indirect
	github.com/maurodelazeri/gorilla-reconnect v0.0.0-20180328170005-42501a5438b9
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
)

//replace github.com/gnanderson/xrpl => ../xrpl
