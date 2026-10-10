package main

import "testing"

func TestEnvCSV(t *testing.T) {
	t.Setenv("T_CSV", " https://a.dev , ,http://b.dev ")
	got := envCSV("T_CSV")
	if len(got) != 2 || got[0] != "https://a.dev" || got[1] != "http://b.dev" {
		t.Fatalf("envCSV = %v", got)
	}
	if v := envCSV("T_CSV_MISSING"); v != nil {
		t.Fatalf("missing key: %v", v)
	}
}
