package users

import "testing"

func TestParsePasswd(t *testing.T) {
	items := ParsePasswd("root:x:0:0:root:/root:/bin/bash\nbad\n")
	if len(items) != 1 || items[0].Name != "root" || items[0].UID != 0 {
		t.Fatalf("unexpected passwd parse: %+v", items)
	}
}

func TestParseGroup(t *testing.T) {
	items := ParseGroup("wheel:x:10:root,nel\n")
	if len(items) != 1 || items[0].Members[1] != "nel" {
		t.Fatalf("unexpected group parse: %+v", items)
	}
}
