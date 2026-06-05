package host

import "testing"

func TestParseOSRelease(t *testing.T) {
	values := ParseOSRelease("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n# comment\n")
	if values["NAME"] != "Ubuntu" || values["VERSION_ID"] != "24.04" {
		t.Fatalf("unexpected os-release parse: %+v", values)
	}
}
