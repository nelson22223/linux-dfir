package disk

import "testing"

func TestParseMounts(t *testing.T) {
	items := ParseMounts("/dev/sda1 / ext4 rw,relatime 0 1\n")
	if len(items) != 1 || items[0].Source != "/dev/sda1" || items[0].Options[0] != "rw" {
		t.Fatalf("unexpected mounts parse: %+v", items)
	}
}

func TestParseMountInfo(t *testing.T) {
	items := ParseMountInfo("36 25 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n")
	if len(items) != 1 || items[0].MountID != "36" || items[0].FSType != "ext4" {
		t.Fatalf("unexpected mountinfo parse: %+v", items)
	}
}
