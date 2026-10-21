package main

import "time"

func seed(demo bool) State {
	s := State{Demo: demo, Targets: []Target{}, Assets: []Asset{}, Findings: []Finding{}, Scans: []Scan{}, Events: []Event{}, Audit: []Event{}, Settings: Settings{Name: "Acme Security", Rate: 20, Concurrency: 5, Retention: 90}}
	if !demo {
		s.Settings.Name = "My workspace"
		return s
	}
	ago := func(h int) string { return time.Now().Add(-time.Duration(h) * time.Hour).UTC().Format(time.RFC3339) }
	s.Targets = []Target{{"target-acme", "acme.example", "verified", "surfacer-verification=demo-only", "Daily", ago(2), 8, true, ago(2), false}, {"target-acme-cloud", "acme-cloud.example", "verified", "surfacer-verification=demo-only", "Weekly", ago(26), 4, true, ago(26), false}, {"target-acme-dev", "acme-dev.example", "pending", "surfacer-verification=demo-only", "Manual", "", 0, true, "", false}}
	hosts := []string{"api.acme.example", "app.acme.example", "staging.acme.example", "cdn.acme.example", "docs.acme.example", "auth.acme.example", "status.acme.example", "acme.example", "dashboard.acme-cloud.example", "storage.acme-cloud.example", "api.acme-cloud.example", "acme-cloud.example"}
	techs := [][]string{{"Nginx", "Node.js"}, {"Next.js", "React"}, {"Apache", "PHP"}, {"Cloudflare"}, {"Next.js"}, {"Nginx", "Express"}, {"Vercel"}, {"Next.js", "React"}, {"React", "Nginx"}, {"Amazon S3"}, {"Go", "Nginx"}, {"Next.js"}}
	counts := []int{2, 0, 3, 0, 0, 1, 0, 0, 1, 1, 0, 0}
	severities := []string{"high", "none", "critical", "none", "none", "medium", "none", "none", "medium", "high", "none", "none"}
	for i, host := range hosts {
		target := "target-acme"
		if i > 7 {
			target = "target-acme-cloud"
		}
		status := 200
		if i == 5 {
			status = 302
		}
		if i == 9 {
			status = 403
		}
		ports := []int{443}
		if i == 2 {
			ports = []int{80, 443, 8080}
		}
		s.Assets = append(s.Assets, Asset{ID: "asset-" + host, Host: host, Type: "Web service", IP: []string{"203.0.113.12", "198.51.100.24", "192.0.2.18"}[i%3], Status: status, Technologies: techs[i], Ports: ports, Findings: counts[i], Severity: severities[i], FirstSeen: ago(240 + i*3), LastSeen: ago(2), TLS: ago(-1200), Source: "subfinder · crt.sh, DNS", TargetID: target, Title: []string{"Acme API", "Acme Workspace", "Staging environment", "Acme CDN", "Developer documentation", "Authentication service", "System status", "Acme", "Cloud dashboard", "Object storage", "Cloud API", "Acme Cloud"}[i]})
	}
	s.Findings = []Finding{
		{ID: "f1", Title: "Exposed environment file", Severity: "critical", Host: "staging.acme.example", Status: "open", Template: "exposed-env", FirstSeen: ago(2), LastSeen: ago(2), Description: "The staging web service returns an environment configuration file. This can disclose service credentials and internal configuration. This is sample evidence from the demo dataset.", Remediation: "Remove the environment file from the public web root. Deny access to dotfiles at the web server, then rotate any credentials that may have been exposed.", Evidence: "GET /.env HTTP/1.1\nHost: staging.acme.example\nX-Scanner: Surfacer/demo\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nAPP_ENV=staging\nDATABASE_PASSWORD=[REDACTED]\nAPI_SECRET=[REDACTED]", Notes: []Note{}},
		{ID: "f2", Title: "Outdated Nginx version", Severity: "high", Host: "api.acme.example", Status: "open", Template: "nginx-version", FirstSeen: ago(48), LastSeen: ago(2), Description: "The Server response header reports an outdated Nginx release. Confirm the installed package and any vendor backports before treating this as an exploitable issue.", Remediation: "Upgrade to a supported Nginx release and suppress the server version header. Confirm package security patches with your platform team.", Evidence: "GET / HTTP/1.1\nHost: api.acme.example\n\nHTTP/1.1 200 OK\nServer: nginx/1.18.0", Notes: []Note{}},
		{ID: "f3", Title: "Public object storage listing", Severity: "high", Host: "storage.acme-cloud.example", Status: "open", Template: "s3-listing", FirstSeen: ago(24), LastSeen: ago(2), Description: "Sample storage configuration allows anonymous listing of object names. Review the policy and determine whether public access is intended.", Remediation: "Enable Block Public Access and limit bucket policies to the minimum required principals.", Evidence: "HTTP/1.1 200 OK\nContent-Type: application/xml\n\n<ListBucketResult><Name>acme-public</Name><Key>exports/</Key></ListBucketResult>", Notes: []Note{}},
		{ID: "f4", Title: "Debug endpoint enabled", Severity: "high", Host: "staging.acme.example", Status: "open", Template: "debug-endpoint", FirstSeen: ago(2), LastSeen: ago(2), Description: "A debug endpoint is available on the staging service. It reveals application internals in this sample dataset.", Remediation: "Disable debug mode and remove debug endpoints from internet-facing deployments.", Evidence: "GET /debug HTTP/1.1\n\nHTTP/1.1 200 OK\nDebug mode: enabled", Notes: []Note{}},
		{ID: "f5", Title: "Missing Content Security Policy", Severity: "medium", Host: "dashboard.acme-cloud.example", Status: "open", Template: "csp-missing", FirstSeen: ago(96), LastSeen: ago(2), Description: "The service response does not set a Content-Security-Policy header. This is a hardening recommendation, not proof of a cross-site scripting vulnerability.", Remediation: "Define an application-specific Content Security Policy and validate it in report-only mode before enforcement.", Evidence: "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Security-Policy: [absent]", Notes: []Note{}},
		{ID: "f6", Title: "TLS certificate expiring soon", Severity: "medium", Host: "auth.acme.example", Status: "open", Template: "tls-expiry", FirstSeen: ago(24), LastSeen: ago(2), Description: "The demo certificate expires within 14 days. Renew it to avoid interrupted authentication.", Remediation: "Renew the certificate and verify automated renewal is configured.", Evidence: "Subject: auth.acme.example\nCertificate expires in: 12 days", Notes: []Note{}},
		{ID: "f7", Title: "Directory listing enabled", Severity: "medium", Host: "staging.acme.example", Status: "accepted risk", Template: "directory-listing", FirstSeen: ago(120), LastSeen: ago(2), Description: "The sample staging service exposes a directory index.", Remediation: "Disable autoindex and require authorization for staging resources.", Evidence: "HTTP/1.1 200 OK\nIndex of /uploads", Notes: []Note{{"Time-limited acceptance for staging migration. Review with platform team.", ago(24), "Alex Morgan"}}},
		{ID: "f8", Title: "Server version disclosure", Severity: "low", Host: "api.acme.example", Status: "false positive", Template: "server-header", FirstSeen: ago(120), LastSeen: ago(2), Description: "A response header discloses a server version.", Remediation: "Consider suppressing detailed version information.", Evidence: "Server: nginx", Notes: []Note{{"Version is intentionally exposed; no actionable vulnerability confirmed.", ago(48), "Alex Morgan"}}},
		{ID: "f9", Title: "Exposed Git configuration", Severity: "high", Host: "app.acme.example", Status: "resolved", Template: "git-config", FirstSeen: ago(200), LastSeen: ago(72), Description: "Previously accessible Git configuration is absent in two successful demo scans.", Remediation: "Keep version control metadata outside the web root.", Evidence: "GET /.git/config\nHTTP/1.1 404 Not Found", Notes: []Note{}},
	}
	for i, t := range s.Targets[:2] {
		sc := newScan(t, "Scheduled", 20)
		sc.ID = "scan-history-" + t.ID
		sc.Status = "completed"
		sc.Progress = 100
		sc.StartedAt = ago(3 + i*24)
		sc.FinishedAt = ago(2 + i*24)
		sc.Assets = t.Assets
		sc.Findings = 6 - i*4
		for j := range sc.Stages {
			sc.Stages[j].Status = "completed"
		}
		s.Scans = append(s.Scans, sc)
	}
	s.Events = []Event{{ID: "e1", Kind: "finding", Title: "New critical exposure", Detail: "Environment file exposed on staging.acme.example", At: ago(2), Actor: "Surfacer"}, {ID: "e2", Kind: "asset", Title: "New asset discovered", Detail: "staging.acme.example · 3 open ports", At: ago(2), Actor: "Surfacer"}, {ID: "e3", Kind: "finding", Title: "New high exposure", Detail: "Debug endpoint enabled on staging.acme.example", At: ago(2), Actor: "Surfacer"}, {ID: "e4", Kind: "resolved", Title: "Finding resolved", Detail: "Exposed Git configuration on app.acme.example", At: ago(26), Actor: "Surfacer"}, {ID: "e5", Kind: "asset", Title: "New asset discovered", Detail: "storage.acme-cloud.example · Amazon S3", At: ago(26), Actor: "Surfacer"}, {ID: "e6", Kind: "port", Title: "New port discovered", Detail: "Port 8080 opened on staging.acme.example", At: ago(26), Actor: "Surfacer"}, {ID: "e7", Kind: "certificate", Title: "Certificate expires soon", Detail: "auth.acme.example · expires in 12 days", At: ago(26), Actor: "Surfacer"}}
	s.Audit = []Event{{ID: "a1", Kind: "audit", Title: "Demo scan completed", Detail: "acme.example · 20 req/s · simulated tools", At: ago(2), Actor: "Surfacer"}, {ID: "a2", Kind: "audit", Title: "Finding triaged", Detail: "Directory listing enabled: accepted risk", At: ago(24), Actor: "Alex Morgan"}, {ID: "a3", Kind: "audit", Title: "Demo scan completed", Detail: "acme-cloud.example · 20 req/s · simulated tools", At: ago(26), Actor: "Surfacer"}, {ID: "a4", Kind: "audit", Title: "Sample workspace created", Detail: "Demo dataset · no external scan traffic", At: ago(240), Actor: "Surfacer"}}
	return s
}
