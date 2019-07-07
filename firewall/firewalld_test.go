package firewall

import (
	"strconv"
	"testing"
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

func genBlackList() *blacklist {
	bl := &blacklist{
		entries:  make(map[string]*blEntry),
		duration: time.Second * 2,
	}

	for i := 0; i < 10; i++ {
		p := &xrpl.Peer{PublicKey: strconv.Itoa(i)}
		bl.add(p)
	}

	return bl
}

func TestBlackListExpire(t *testing.T) {
	bl := genBlackList()

	select {
	case <-time.After(time.Second * 2):
	}

	bl.expireEntries()

	if len(bl.entries) > 0 {
		t.Fatalf("unexpected number of blacklist entries '%d'", len(bl.entries))
	}
}
