package cmd

import (
	"os"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

type gString func(string) string
type gInt func(string) int
type gBool func(string) bool

var getString gString = func(key string) string { return viper.GetString(key) }
var getInt gInt = func(key string) int { return viper.GetInt(key) }
var getBool gBool = func(key string) bool { return viper.GetBool(key) }

var cfgTests = []struct {
	key string
	val interface{}
	f   interface{}
}{
	{"user", "testnetadmin", getString},
	{"passwd", "testnetpasswd", getString},
	{"addr", "192.168.254.10", getString},
	{"port", 6006, getInt},
	{"tls", true, getBool},
	{"banlength", 1440, getInt},
	{"repeat", 60, getInt},
	{"docker", "rippled", getString},
	{"tcpkill", false, getBool},
}

// well this is a little verbose but I don't want to break the example config
func TestExampleConfig(t *testing.T) {
	cfgFile = "../examples/.rbh.yaml"
	initConfig()

	tf := func(key string, result interface{}, val interface{}) {
		resultKind := reflect.TypeOf(result).Kind()
		valKind := reflect.TypeOf(val).Kind()
		if resultKind != valKind || result != val {
			t.Errorf("unexpected type from config '%s' - %T, expected %T", key, resultKind, valKind)
		}
	}

	for _, tt := range cfgTests {
		t.Run(tt.key, func(t *testing.T) {
			var strResult string
			var intResult int
			var boolResult bool

			switch f := tt.f.(type) {
			case gString:
				strResult = f(tt.key)
				tf(tt.key, strResult, tt.val)
			case gInt:
				intResult = f(tt.key)
				tf(tt.key, intResult, tt.val)
			case gBool:
				boolResult = f(tt.key)
				tf(tt.key, boolResult, tt.val)
			}
		})
	}
}

var whitelistTests = []struct {
	ip string
}{
	{"10.0.0.10"},
	{"10.0.0.20"},
	{"10.0.0.30"},
}

func TestWhitelistFromConfig(t *testing.T) {
	cfgFile = "../examples/.rbh.yaml"
	initConfig()
	list := viper.GetStringSlice("whitelist")

	for i, tt := range whitelistTests {
		if list[i] != tt.ip {
			t.Errorf("expecting IP %s, got %s", tt.ip, list[i])
		}
	}
}

func TestWhitelistFromEnv(t *testing.T) {
	cfgFile = "/not-exist"
	os.Setenv("RBH_WHITELIST", "10.0.0.10 10.0.0.20 10.0.0.30")
	initConfig()
	list := viper.GetStringSlice("whitelist")

	for i, tt := range whitelistTests {
		if list[i] != tt.ip {
			t.Errorf("expecting IP %s, got %s", tt.ip, list[i])
		}
	}
}
