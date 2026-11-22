package api_test

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthIsNotFailedByAbsentDatabase(t *testing.T) {
	h := startNode(t, filepath.Join(t.TempDir(), "zones"))
	c, out := call(t, h, "GET", "/api/v1/health", "")
	if c != http.StatusOK {
		t.Fatalf("health %d %v", c, out)
	}
	if out["status"] == "degraded" || out["status"] == "unhealthy" {
		t.Fatalf("health status %v with the database disabled: %v", out["status"], out)
	}
	db, _ := out["checks"].(map[string]any)["database"].(map[string]any)
	if db == nil || db["status"] != "disabled" {
		t.Fatalf("database check %v, want status disabled", db)
	}
}

func TestQueryHistoryIsUnavailableWithoutDatabase(t *testing.T) {
	h := startNode(t, filepath.Join(t.TempDir(), "zones"))
	c, out := call(t, h, "GET", "/api/v1/query-logs", "")
	if c != http.StatusServiceUnavailable {
		t.Fatalf("query-logs %d %v, want 503", c, out)
	}
	if out["error"] != "query_history_unavailable" || out["available"] != false {
		t.Fatalf("body %v", out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "Observability Profile") {
		t.Fatalf("message %q does not mention the Observability Profile", msg)
	}
}

func TestSettingsReportQueryHistoryUnavailable(t *testing.T) {
	h := startNode(t, filepath.Join(t.TempDir(), "zones"))
	c, out := call(t, h, "GET", "/api/v1/settings", "")
	if c != http.StatusOK {
		t.Fatalf("settings %d %v", c, out)
	}
	if out["query_history_available"] != false {
		t.Fatalf("query_history_available = %v", out["query_history_available"])
	}
}
