package store

import (
	"context"
	"os"
	"testing"
	"time"

	"sinkhole/src/server/filter"
)

func TestStoreCRUD(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sinkhole_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	s, err := Open(tempDir)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer s.Close()

	// 1. Settings test
	if err := s.SetSetting("test_key", "test_val"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, err := s.GetSetting("test_key")
	if err != nil || v != "test_val" {
		t.Fatalf("GetSetting: val=%s err=%v", v, err)
	}

	// 2. Blocklist test
	bl, err := s.AddBlocklist("Test List", "https://example.com/hosts", true)
	if err != nil {
		t.Fatalf("AddBlocklist: %v", err)
	}
	lists, err := s.ListBlocklists()
	if err != nil || len(lists) != 1 {
		t.Fatalf("ListBlocklists: len=%d err=%v", len(lists), err)
	}
	if err := s.UpdateBlocklist(bl.ID, "Renamed List", false); err != nil {
		t.Fatalf("UpdateBlocklist: %v", err)
	}
	blUpdated, _ := s.GetBlocklist(bl.ID)
	if blUpdated.Name != "Renamed List" || blUpdated.Enabled != false {
		t.Fatalf("Blocklist update mismatch: %+v", blUpdated)
	}

	// 3. Custom rules test
	rule, err := s.AddRule(filter.CustomRule{Domain: "ads.test", Action: "block", Subdomains: true, Comment: "test rule"})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	rules, err := s.ListRules()
	if err != nil || len(rules) != 1 || rules[0].Domain != "ads.test" {
		t.Fatalf("ListRules: len=%d err=%v", len(rules), err)
	}
	if err := s.DeleteRule(rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	rules, _ = s.ListRules()
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules after deletion, got %d", len(rules))
	}

	// 4. Query log batching test
	batch := []QueryEntry{
		{
			TS:        time.Now().UnixMilli(),
			Client:    "192.168.1.50",
			Domain:    "doubleclick.net",
			QType:     "A",
			Status:    "blocked",
			Reason:    "list_block",
			RCode:     "NOERROR",
			LatencyUs: 120,
			Answer:    "0.0.0.0",
		},
		{
			TS:        time.Now().UnixMilli(),
			Client:    "192.168.1.50",
			Domain:    "example.com",
			QType:     "A",
			Status:    "allowed",
			Upstream:  "1.1.1.1:53",
			RCode:     "NOERROR",
			LatencyUs: 14000,
			Answer:    "93.184.216.34",
		},
	}
	if err := s.InsertQueries(batch); err != nil {
		t.Fatalf("InsertQueries: %v", err)
	}

	logs, err := s.QueryLog(context.Background(), QueryFilter{Limit: 10})
	if err != nil || len(logs) != 2 {
		t.Fatalf("QueryLog: len=%d err=%v", len(logs), err)
	}

	// Filter by status
	blockedLogs, _ := s.QueryLog(context.Background(), QueryFilter{Status: "blocked"})
	if len(blockedLogs) != 1 || blockedLogs[0].Domain != "doubleclick.net" {
		t.Fatalf("Blocked query filter mismatch: %+v", blockedLogs)
	}
}
