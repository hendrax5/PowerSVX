package config

import "testing"

func TestNormalizeForwardZones(t *testing.T) {
	got, err := NormalizeForwardZones([]ForwardZoneConfig{
		{Zone: "Corp.Example.com", Forwarders: []string{"10.0.0.1"}},
		{Zone: "corp.example.com", Forwarders: []string{"10.0.0.2:53"}}, // dup ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Zone != "corp.example.com." || got[0].Forwarders[0] != "10.0.0.1:53" {
		t.Fatalf("%+v", got)
	}
	_, err = NormalizeForwardZones([]ForwardZoneConfig{{Zone: ".", Forwarders: []string{"1.1.1.1"}}})
	if err == nil {
		t.Fatal("root zone should fail")
	}
}
