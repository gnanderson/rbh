## rbh run

run the automatic ban hammer

### Synopsis

run command will run as a service connecting to the XRPL node specifid.

Periodically this service will query the XRPL node for a list of peers and decide
whether to swing the ban hammer.

```
rbh run [flags]
```

### Options

```
  -b, --banlength int   the duration of the ban (in minutes) for unstable peers (default 1440)
  -h, --help            help for run
  -r, --repeat int      check for new peers to ban after 'repeat' seconds (default 60)
```

### Options inherited from parent commands

```
  -a, --addr string     admin websocket RPC service address (default "127.0.0.1")
  -c, --config string   config file (default is $HOME/.rbh.yaml)
  -p, --port string     admin websocket RPC service port (default "6006")
  -t, --tls             use wss scheme, ommiting this flag assumes running on localhost
```

### SEE ALSO

* [rbh](rbh.md)	 - rbh gives errant XRPL (rippled) nodes "Ye Olde Ban Hammer"

###### Auto generated by spf13/cobra on 7-Jul-2019