module github.com/gnanderson/rbh

go 1.13

require (
	github.com/gnanderson/xrpl v0.0.0
	github.com/godbus/dbus v5.0.1+incompatible
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
)

replace github.com/gnanderson/xrpl v0.0.0 => ../xrpl
