package main

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestPDFReportFiltersAndPrivacy(t *testing.T) {
	state := emptyState()
	state.Targets = []Target{{ID: "target", Domain: "owned.example"}}
	state.Findings = []Finding{{TargetID: "target", Host: "owned.example", Severity: "high", Title: "Observed exposure", Status: "open", Description: "Actual observation", Evidence: "PRIVATE_RAW_CREDENTIAL", Notes: []Note{{Text: "PRIVATE_ANALYST_NOTE"}}}}
	request := httptest.NewRequest("GET", "/api/reports.pdf?targetId=target&severity=high&status=open", nil)
	response := httptest.NewRecorder()
	reportPDF(response, request, state)
	if response.Code != 200 || response.Header().Get("Content-Type") != "application/pdf" || !strings.HasPrefix(response.Body.String(), "%PDF-") {
		t.Fatal("invalid PDF report")
	}
	decoded := ""
	for _, stream := range regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`).FindAllSubmatch(response.Body.Bytes(), -1) {
		reader, err := zlib.NewReader(bytes.NewReader(stream[1]))
		if err != nil {
			continue
		}
		text, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		decoded += string(text)
	}
	if !strings.Contains(decoded, "Observed exposure") {
		t.Fatal("PDF omitted matching finding")
	}
	if strings.Contains(decoded, "PRIVATE_RAW_CREDENTIAL") || strings.Contains(decoded, "PRIVATE_ANALYST_NOTE") {
		t.Fatal("private evidence included in report")
	}
	response = httptest.NewRecorder()
	reportPDF(response, httptest.NewRequest("GET", "/api/reports.pdf?targetId=unknown", nil), state)
	if response.Code != 404 {
		t.Fatal("unknown report scope accepted")
	}
	response = httptest.NewRecorder()
	reportPDF(response, httptest.NewRequest("GET", "/api/reports.pdf?severity=invalid", nil), state)
	if response.Code != 400 {
		t.Fatal("invalid report filter accepted")
	}
}
