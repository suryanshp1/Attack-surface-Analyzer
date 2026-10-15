package main

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"codeberg.org/go-pdf/fpdf"
)

func reportPDF(w http.ResponseWriter, r *http.Request, state State) {
	target := r.URL.Query().Get("targetId")
	if target != "" {
		found := false
		for _, t := range state.Targets {
			if t.ID == target {
				found = true
			}
		}
		if !found {
			fail(w, 404, "Target not found")
			return
		}
	}
	severity, status := r.URL.Query().Get("severity"), r.URL.Query().Get("status")
	if severity != "" && !contains([]string{"critical", "high", "medium", "low", "info"}, severity) {
		fail(w, 400, "Invalid severity filter")
		return
	}
	if status != "" && !contains([]string{"open", "resolved", "accepted risk", "false positive"}, status) {
		fail(w, 400, "Invalid status filter")
		return
	}
	assets := []Asset{}
	findings := []Finding{}
	for _, a := range state.Assets {
		if target == "" || a.TargetID == target {
			assets = append(assets, a)
		}
	}
	for _, f := range state.Findings {
		if (target == "" || f.TargetID == target) && (severity == "" || f.Severity == severity) && (status == "" || f.Status == status) {
			findings = append(findings, f)
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Host < assets[j].Host })
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(findings, func(i, j int) bool {
		if rank[findings[i].Severity] != rank[findings[j].Severity] {
			return rank[findings[i].Severity] < rank[findings[j].Severity]
		}
		return findings[i].Host < findings[j].Host
	})
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(18, 18, 18)
	pdf.SetAutoPageBreak(true, 18)
	pdf.SetTitle("Surfacer exposure report", true)
	pdf.SetAuthor("Surfacer", true)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	line := func(text string, size float64, bold bool) {
		style := ""
		if bold {
			style = "B"
		}
		pdf.SetFont("Helvetica", style, size)
		pdf.MultiCell(174, 6, tr(redact(capString(text, 3000))), "", "L", false)
	}
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(0, 5, fmt.Sprintf("Surfacer | page %d", pdf.PageNo()), "", 0, "R", false, 0, "")
	})
	pdf.AddPage()
	line("SURFACER / EXPOSURE REPORT", 20, true)
	pdf.Ln(5)
	line(state.Settings.Name, 12, true)
	line("Generated "+time.Now().UTC().Format(time.RFC3339), 9, false)
	scope := "All targets"
	for _, t := range state.Targets {
		if t.ID == target {
			scope = t.Domain
		}
	}
	line(fmt.Sprintf("Scope: %s | severity: %s | status: %s", scope, defaultFilter(severity), defaultFilter(status)), 9, false)
	line(fmt.Sprintf("%d current assets | %d matching findings", len(assets), len(findings)), 12, true)
	line("Findings are scanner observations, not proof of exploitability. Partial scans retain prior findings. This report omits raw evidence, credentials, notes and historical URLs.", 9, false)
	pdf.Ln(5)
	line("Scan coverage", 14, true)
	n := 0
	for _, sc := range state.Scans {
		if target != "" && sc.TargetID != target {
			continue
		}
		line(fmt.Sprintf("%s | %s | %s | %d assets | %d findings", sc.Domain, sc.Status, sc.StartedAt, sc.Assets, sc.Findings), 9, false)
		n++
		if n == 20 {
			break
		}
	}
	if n == 0 {
		line("No scans recorded for this scope.", 10, false)
	}
	pdf.Ln(5)
	line("Current inventory", 14, true)
	for i, a := range assets {
		if i == 1000 {
			line("Inventory truncated after 1000 assets; use CSV for the full inventory.", 10, true)
			break
		}
		if pdf.GetY() > 258 {
			pdf.AddPage()
		}
		line(a.Host, 11, true)
		line(fmt.Sprintf("%s | IP %s | ports %s | %s", a.Type, a.IP, reportValue(strings.Join(intStrings(a.Ports), ", ")), reportValue(strings.Join(a.Technologies, ", "))), 9, false)
	}
	if len(assets) == 0 {
		line("No observed assets in this scope.", 10, false)
	}
	pdf.AddPage()
	line("Findings", 18, true)
	pdf.Ln(4)
	for i, f := range findings {
		if i == 1000 {
			line("Findings truncated after 1000 rows; use CSV for all findings.", 10, true)
			break
		}
		if pdf.GetY() > 245 {
			pdf.AddPage()
		}
		line(strings.ToUpper(f.Severity)+" / "+f.Title, 12, true)
		line(f.Host+" | "+f.Status+" | "+f.Template, 9, false)
		line("First observed "+f.FirstSeen+" | last observed "+f.LastSeen, 8, false)
		line(f.Description, 10, false)
		if f.Remediation != "" {
			line("Remediation: "+f.Remediation, 10, false)
		}
		pdf.Ln(5)
	}
	if len(findings) == 0 {
		line("No findings match these filters.", 10, false)
	}
	var output bytes.Buffer
	if err := pdf.Output(&output); err != nil {
		fail(w, 500, "Could not generate report")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="surfacer-report.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(output.Bytes())
}
func defaultFilter(value string) string {
	if value == "" {
		return "all"
	}
	return value
}

func reportValue(value string) string {
	if value == "" {
		return "not observed"
	}
	return value
}
