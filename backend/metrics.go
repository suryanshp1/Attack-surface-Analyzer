package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Metrics contain counts and health only: no domains, members, evidence or secrets.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request, actor Actor) {
	if actor.Role != "owner" {
		fail(w, 403, "Owner access required")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	metric := func(name string, value int) { fmt.Fprintf(w, "# TYPE %s gauge\n%s %d\n", name, name, value) }
	metric("surfacer_targets", len(s.state.Targets))
	metric("surfacer_assets", len(s.publicState().Assets))
	metric("surfacer_historical_urls", len(s.visibleEndpoints(s.state.History)))
	metric("surfacer_workers_online", s.publicState().Runtime.Workers)
	for _, status := range []string{"queued", "running", "completed", "partial", "failed", "canceled"} {
		n := 0
		for _, sc := range s.state.Scans {
			if sc.Status == status && !s.recordDeleted("scans", sc.ID) {
				n++
			}
		}
		fmt.Fprintf(w, "surfacer_scans{status=%s} %d\n", strconv.Quote(status), n)
	}
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		n := 0
		for _, f := range s.state.Findings {
			if f.Status == "open" && f.Severity == severity && f.DeletedAt == "" {
				n++
			}
		}
		fmt.Fprintf(w, "surfacer_open_findings{severity=%s} %d\n", strconv.Quote(severity), n)
	}

	// Database connection pool stats if live PostgreSQL backend is active
	if s.db != nil {
		stat := s.db.Stat()
		fmt.Fprintf(w, "# TYPE surfacer_db_pool_total_connections gauge\nsurfacer_db_pool_total_connections %d\n", stat.TotalConns())
		fmt.Fprintf(w, "# TYPE surfacer_db_pool_idle_connections gauge\nsurfacer_db_pool_idle_connections %d\n", stat.IdleConns())
		fmt.Fprintf(w, "# TYPE surfacer_db_pool_acquired_connections gauge\nsurfacer_db_pool_acquired_connections %d\n", stat.AcquiredConns())
	}

	// Append operational telemetry (RED metrics, gateway counters, stage durations, runtime)
	GlobalTelemetry.WritePrometheus(w)

	fmt.Fprintf(w, "surfacer_metrics_timestamp_seconds %d\n", time.Now().Unix())
}
