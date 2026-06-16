package file

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)



type ScanResult struct {
	FilePath    string
	Meta        FileMeta
	Strings     StringAnalysis
	IOCs        []IOC
	Findings    []Finding
	Score       Score
}

type FileMeta struct {
	FileName  string
	FileType  string
	FileSize  int64
	MD5       string
	SHA1      string
	SHA256    string
	MagicBytes string
	Entropy   float64
	Packed    bool
	Sections  []string
}

type StringAnalysis struct {
	Total     int
	URLs      []string
	IPs       []string
	Emails    []string
	Domains   []string
	Endpoints []string
	Secrets   []SuspiciousString
}

type SuspiciousString struct {
	Value    string
	Category string
	Severity string
}

type IOC struct {
	Type     string
	Value    string
	Context  string
	Severity string
}

type Finding struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Category    string
	Remediation string
}

type Score struct {
	Overall   float64
	RiskLevel string
	RiskLabel string
}



var magicSignatures = []struct {
	Magic    []byte
	Offset   int
	FileType string
}{
	{[]byte{0x4D, 0x5A}, 0, "PE Executable (Windows EXE/DLL)"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, 0, "ELF Executable (Linux/Unix)"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "ZIP Archive / APK / DOCX / XLSX"},
	{[]byte{0x25, 0x50, 0x44, 0x46}, 0, "PDF Document"},
	{[]byte{0x52, 0x61, 0x72, 0x21}, 0, "RAR Archive"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF}, 0, "7-Zip Archive"},
	{[]byte{0x64, 0x65, 0x78, 0x0A}, 0, "Dalvik DEX (Android)"},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, 0, "Mach-O 64-bit (macOS)"},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, 0, "Java Class / Mach-O FAT"},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0}, 0, "Microsoft Office (DOC/XLS/PPT)"},
	{[]byte{0x1F, 0x8B}, 0, "GZIP Archive"},
	{[]byte{0x42, 0x5A, 0x68}, 0, "BZIP2 Archive"},
	{[]byte{0xFF, 0xFE}, 0, "Unicode Text (UTF-16 LE)"},
	{[]byte{0xEF, 0xBB, 0xBF}, 0, "Unicode Text (UTF-8 BOM)"},
}



var (
	urlRe       = regexp.MustCompile(`https?://[a-zA-Z0-9.\-_/?=&#%+@:]{8,}`)
	ipRe        = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	emailRe     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	domainRe    = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|app|dev|xyz|info|biz)`)
	apiRe       = regexp.MustCompile(`(?i)/(?:api|v\d|rest|graphql)/[a-zA-Z0-9/_\-]+`)
	awsKeyRe    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	googleKeyRe = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	githubRe    = regexp.MustCompile(`gh[ps]_[A-Za-z0-9]{36,}`)
	jwtRe       = regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*`)
	privateKeyRe = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`)
)


var suspiciousWinStrings = []struct {
	Pattern  *regexp.Regexp
	Category string
	Severity string
}{
	{regexp.MustCompile(`(?i)cmd\.exe|powershell|wscript|cscript`), "Shell Execution", "critical"},
	{regexp.MustCompile(`(?i)VirtualAlloc|WriteProcessMemory|CreateRemoteThread`), "Process Injection", "critical"},
	{regexp.MustCompile(`(?i)URLDownloadToFile|InternetOpenUrl|WinHttpOpen`), "Network Download", "high"},
	{regexp.MustCompile(`(?i)RegSetValue|RegCreateKey|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`), "Registry Persistence", "high"},
	{regexp.MustCompile(`(?i)CreateService|OpenSCManager|StartService`), "Service Installation", "high"},
	{regexp.MustCompile(`(?i)CryptEncrypt|CryptGenKey|BCryptEncrypt`), "Cryptographic Operations", "medium"},
	{regexp.MustCompile(`(?i)GetAsyncKeyState|SetWindowsHookEx|GetForegroundWindow`), "Keylogger Indicators", "critical"},
	{regexp.MustCompile(`(?i)IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess`), "Anti-Debug", "high"},
	{regexp.MustCompile(`(?i)schtasks|at\.exe|taskschd`), "Scheduled Task", "high"},
	{regexp.MustCompile(`(?i)netsh|ipconfig|systeminfo|whoami|net user`), "Recon Commands", "medium"},
	{regexp.MustCompile(`(?i)mimikatz|sekurlsa|lsadump`), "Credential Dumping Tool", "critical"},
	{regexp.MustCompile(`(?i)base64|FromBase64String|Convert\.FromBase64`), "Base64 Encoding", "medium"},
	{regexp.MustCompile(`(?i)socket|WSAStartup|connect|recv|send`), "Raw Socket", "medium"},
	{regexp.MustCompile(`(?i)shadow|vssadmin|wbadmin|bcdedit`), "Backup Deletion", "critical"},
}


var suspiciousPDFStrings = []struct {
	Pattern  *regexp.Regexp
	Category string
	Severity string
}{
	{regexp.MustCompile(`(?i)/JavaScript|/JS\s`), "Embedded JavaScript", "critical"},
	{regexp.MustCompile(`(?i)/OpenAction|/AA\s`), "Auto-Action", "high"},
	{regexp.MustCompile(`(?i)/Launch|/SubmitForm|/ImportData`), "External Action", "high"},
	{regexp.MustCompile(`(?i)/EmbeddedFile|/Filespec`), "Embedded File", "medium"},
	{regexp.MustCompile(`(?i)/Encrypt`), "Encryption Present", "medium"},
	{regexp.MustCompile(`(?i)eval\(|unescape\(|String\.fromCharCode`), "JS Obfuscation", "critical"},
	{regexp.MustCompile(`(?i)/URI\s*\(http`), "External URL", "medium"},
}



type Analyzer struct{}

func NewAnalyzer() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Scan(filePath string) (*ScanResult, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot access file: %w", err)
	}

	result := &ScanResult{
		FilePath: filePath,
		Meta: FileMeta{
			FileName: filepath.Base(filePath),
			FileSize: info.Size(),
		},
		Score: Score{},
	}


	maxRead := int64(100 * 1024 * 1024)
	if info.Size() < maxRead {
		maxRead = info.Size()
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make([]byte, maxRead)
	n, _ := f.Read(data)
	data = data[:n]


	if err := a.computeHashes(filePath, &result.Meta); err != nil {
		return nil, err
	}


	result.Meta.FileType = a.detectFileType(data, filePath)
	if len(data) >= 4 {
		result.Meta.MagicBytes = fmt.Sprintf("%02X %02X %02X %02X", data[0], data[1], data[2], data[3])
	}


	result.Meta.Entropy = computeEntropy(data)
	result.Meta.Packed = result.Meta.Entropy > 7.2


	strs := extractPrintable(data, 5)
	result.Strings.Total = len(strs)
	combined := strings.Join(strs, "\n")


	a.extractIOCs(combined, result)


	ext := strings.ToLower(filepath.Ext(filePath))
	switch {
	case ext == ".exe" || ext == ".dll" || strings.Contains(result.Meta.FileType, "PE"):
		a.analyzePE(strs, result)
	case ext == ".elf" || strings.Contains(result.Meta.FileType, "ELF"):
		a.analyzeELF(strs, result)
	case ext == ".pdf" || strings.Contains(result.Meta.FileType, "PDF"):
		a.analyzePDF(strs, result)
	case ext == ".apk" || ext == ".zip" || strings.Contains(result.Meta.FileType, "ZIP"):
		a.analyzeZIP(filePath, result)
	case ext == ".doc" || ext == ".xls" || ext == ".ppt":
		a.analyzeOffice(strs, result)
	case ext == ".docx" || ext == ".xlsx" || ext == ".pptx":
		a.analyzeZIP(filePath, result)
	}


	a.detectSecrets(combined, result)


	a.computeScore(result)

	return result, nil
}

func (a *Analyzer) computeHashes(path string, meta *FileMeta) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h1, h2, h3 := md5.New(), sha1.New(), sha256.New()
	w := io.MultiWriter(h1, h2, h3)
	io.Copy(w, f)
	meta.MD5 = fmt.Sprintf("%x", h1.Sum(nil))
	meta.SHA1 = fmt.Sprintf("%x", h2.Sum(nil))
	meta.SHA256 = fmt.Sprintf("%x", h3.Sum(nil))
	return nil
}

func (a *Analyzer) detectFileType(data []byte, path string) string {
	for _, sig := range magicSignatures {
		if len(data) >= sig.Offset+len(sig.Magic) {
			match := true
			for i, b := range sig.Magic {
				if data[sig.Offset+i] != b {
					match = false
					break
				}
			}
			if match {

				ext := strings.ToLower(filepath.Ext(path))
				if sig.FileType == "ZIP Archive / APK / DOCX / XLSX" {
					switch ext {
					case ".apk":
						return "Android APK"
					case ".docx":
						return "Word Document (DOCX)"
					case ".xlsx":
						return "Excel Spreadsheet (XLSX)"
					case ".pptx":
						return "PowerPoint (PPTX)"
					case ".jar":
						return "Java Archive (JAR)"
					}
				}
				return sig.FileType
			}
		}
	}

	printable := 0
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	for _, b := range check {
		if b >= 0x20 && b < 0x7f || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	if float64(printable)/float64(len(check)) > 0.85 {
		return "Text File / Script"
	}
	return "Unknown Binary"
}

func (a *Analyzer) extractIOCs(combined string, result *ScanResult) {
	seen := make(map[string]bool)
	add := func(list *[]string, val string) {
		if !seen[val] {
			seen[val] = true
			*list = append(*list, val)
		}
	}

	for _, u := range urlRe.FindAllString(combined, -1) {
		add(&result.Strings.URLs, u)
		result.IOCs = append(result.IOCs, IOC{Type: "url", Value: u, Severity: "medium"})
	}
	for _, ip := range ipRe.FindAllString(combined, -1) {
		if !isPrivateIP(ip) {
			add(&result.Strings.IPs, ip)
			result.IOCs = append(result.IOCs, IOC{Type: "ip", Value: ip, Severity: "high"})
		}
	}
	for _, e := range emailRe.FindAllString(combined, -1) {
		add(&result.Strings.Emails, e)
	}
	for _, ep := range apiRe.FindAllString(combined, -1) {
		add(&result.Strings.Endpoints, ep)
	}
}

func (a *Analyzer) detectSecrets(combined string, result *ScanResult) {
	checks := []struct {
		Re       *regexp.Regexp
		Category string
		Severity string
	}{
		{awsKeyRe, "AWS Access Key", "critical"},
		{googleKeyRe, "Google API Key", "critical"},
		{githubRe, "GitHub Token", "critical"},
		{jwtRe, "JWT Token", "high"},
		{privateKeyRe, "Private Key", "critical"},
	}
	for _, sc := range checks {
		for _, m := range sc.Re.FindAllString(combined, -1) {
			result.Strings.Secrets = append(result.Strings.Secrets, SuspiciousString{
				Value:    redact(m),
				Category: sc.Category,
				Severity: sc.Severity,
			})
			result.IOCs = append(result.IOCs, IOC{
				Type:     "secret",
				Value:    redact(m),
				Context:  sc.Category,
				Severity: sc.Severity,
			})
		}
	}
}

func (a *Analyzer) analyzePE(strs []string, result *ScanResult) {
	combined := strings.Join(strs, "\n")
	fid := 1
	for _, check := range suspiciousWinStrings {
		if check.Pattern.MatchString(combined) {
			matches := check.Pattern.FindAllString(combined, 3)
			evidence := strings.Join(matches, ", ")
			result.Strings.Secrets = append(result.Strings.Secrets, SuspiciousString{
				Value:    truncStr(evidence, 80),
				Category: check.Category,
				Severity: check.Severity,
			})
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("FILE-%03d", fid),
				Title:       check.Category + " Detected",
				Description: fmt.Sprintf("Suspicious pattern found: %s", truncStr(evidence, 100)),
				Severity:    check.Severity,
				Category:    "pe_analysis",
				Remediation: "Investigate the purpose of this code. Use sandbox for dynamic analysis.",
			})
			fid++
		}
	}

	if result.Meta.Packed {
		result.Findings = append(result.Findings, Finding{
			ID:          fmt.Sprintf("FILE-%03d", fid),
			Title:       "High Entropy — File Likely Packed/Encrypted",
			Description: fmt.Sprintf("Entropy: %.2f/8.0. Files with entropy >7.2 are often packed, encrypted, or obfuscated.", result.Meta.Entropy),
			Severity:    "high",
			Category:    "obfuscation",
			Remediation: "Use unpacker tools (UPX, etc.) or sandbox for dynamic analysis.",
		})
	}
}

func (a *Analyzer) analyzeELF(strs []string, result *ScanResult) {
	combined := strings.Join(strs, "\n")
	elfPatterns := []struct {
		Pattern  *regexp.Regexp
		Category string
		Severity string
	}{
		{regexp.MustCompile(`(?i)/bin/sh|/bin/bash|system\(|popen\(`), "Shell Execution", "critical"},
		{regexp.MustCompile(`(?i)ptrace|PTRACE_TRACEME`), "Anti-Debug (ptrace)", "high"},
		{regexp.MustCompile(`(?i)dlopen|dlsym|LD_PRELOAD`), "Dynamic Loading", "high"},
		{regexp.MustCompile(`(?i)socket|connect|recv|send|inet_addr`), "Network Activity", "medium"},
		{regexp.MustCompile(`(?i)/etc/passwd|/etc/shadow|/proc/`), "Sensitive File Access", "high"},
		{regexp.MustCompile(`(?i)chmod|chown|setuid|setgid`), "Privilege Change", "high"},
		{regexp.MustCompile(`(?i)fork|execve|execl`), "Process Execution", "medium"},
		{regexp.MustCompile(`(?i)cron|systemd|rc\.local|init\.d`), "Persistence Mechanism", "high"},
	}

	fid := 1
	for _, check := range elfPatterns {
		if check.Pattern.MatchString(combined) {
			matches := check.Pattern.FindAllString(combined, 3)
			evidence := strings.Join(matches, ", ")
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("FILE-%03d", fid),
				Title:       check.Category + " Detected",
				Description: fmt.Sprintf("Evidence: %s", truncStr(evidence, 100)),
				Severity:    check.Severity,
				Category:    "elf_analysis",
				Remediation: "Investigate in isolated sandbox environment.",
			})
			fid++
		}
	}
}

func (a *Analyzer) analyzePDF(strs []string, result *ScanResult) {
	combined := strings.Join(strs, "\n")
	fid := 1
	for _, check := range suspiciousPDFStrings {
		if check.Pattern.MatchString(combined) {
			matches := check.Pattern.FindAllString(combined, 3)
			evidence := strings.Join(matches, ", ")
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("FILE-%03d", fid),
				Title:       "PDF: " + check.Category,
				Description: fmt.Sprintf("Suspicious PDF element found: %s", truncStr(evidence, 100)),
				Severity:    check.Severity,
				Category:    "pdf_analysis",
				Remediation: "Open in sandboxed PDF reader. Do not enable JavaScript or macros.",
			})
			fid++
		}
	}


	jsCount := len(regexp.MustCompile(`(?i)/JavaScript|/JS\s`).FindAllString(combined, -1))
	if jsCount > 1 {
		result.Findings = append(result.Findings, Finding{
			ID:          fmt.Sprintf("FILE-%03d", fid),
			Title:       fmt.Sprintf("Multiple JavaScript Blocks (%d)", jsCount),
			Description: "PDF contains multiple JavaScript sections, common in exploit PDFs.",
			Severity:    "critical",
			Category:    "pdf_analysis",
			Remediation: "Do not open this PDF outside of a sandbox.",
		})
	}
}

func (a *Analyzer) analyzeZIP(filePath string, result *ScanResult) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return
	}
	defer r.Close()

	fid := 1
	var execFiles, scriptFiles, hiddenFiles []string

	for _, f := range r.File {
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".dll"):
			execFiles = append(execFiles, f.Name)
		case strings.HasSuffix(name, ".ps1") || strings.HasSuffix(name, ".bat") ||
			strings.HasSuffix(name, ".vbs") || strings.HasSuffix(name, ".js"):
			scriptFiles = append(scriptFiles, f.Name)
		case strings.HasPrefix(filepath.Base(name), "."):
			hiddenFiles = append(hiddenFiles, f.Name)
		}
		result.Meta.Sections = append(result.Meta.Sections, f.Name)
	}

	if len(execFiles) > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          fmt.Sprintf("FILE-%03d", fid),
			Title:       fmt.Sprintf("Executables Inside Archive (%d)", len(execFiles)),
			Description: fmt.Sprintf("Found: %s", strings.Join(execFiles[:min(3, len(execFiles))], ", ")),
			Severity:    "high",
			Category:    "zip_analysis",
			Remediation: "Do not extract or run executables from untrusted archives.",
		})
		fid++
	}
	if len(scriptFiles) > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          fmt.Sprintf("FILE-%03d", fid),
			Title:       fmt.Sprintf("Script Files Inside Archive (%d)", len(scriptFiles)),
			Description: fmt.Sprintf("Found: %s", strings.Join(scriptFiles[:min(3, len(scriptFiles))], ", ")),
			Severity:    "medium",
			Category:    "zip_analysis",
			Remediation: "Review scripts before execution.",
		})
		fid++
	}
	_ = hiddenFiles
	_ = fid
}

func (a *Analyzer) analyzeOffice(strs []string, result *ScanResult) {
	combined := strings.Join(strs, "\n")
	officePatterns := []struct {
		Pattern  *regexp.Regexp
		Category string
		Severity string
	}{
		{regexp.MustCompile(`(?i)AutoOpen|AutoExec|Auto_Open|Workbook_Open`), "Auto-Execute Macro", "critical"},
		{regexp.MustCompile(`(?i)Shell\(|CreateObject|WScript\.Shell`), "Shell Execution via Macro", "critical"},
		{regexp.MustCompile(`(?i)powershell|cmd\.exe|mshta`), "Command Execution", "critical"},
		{regexp.MustCompile(`(?i)URLDownloadToFile|MSXML2\.XMLHTTP|WinHttp`), "Network Download", "high"},
		{regexp.MustCompile(`(?i)Base64|Chr\(|Asc\(|Xor`), "Obfuscation", "medium"},
	}

	fid := 1
	for _, check := range officePatterns {
		if check.Pattern.MatchString(combined) {
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("FILE-%03d", fid),
				Title:       "Office Macro: " + check.Category,
				Description: "Suspicious macro code detected in Office document.",
				Severity:    check.Severity,
				Category:    "macro_analysis",
				Remediation: "Do not enable macros. Open in protected view only.",
			})
			fid++
		}
	}
}

func (a *Analyzer) computeScore(result *ScanResult) {
	score := 0.0

	sevWeights := map[string]float64{
		"critical": 25, "high": 15, "medium": 8, "low": 3,
	}
	for _, f := range result.Findings {
		score += sevWeights[f.Severity]
	}


	score += float64(len(result.Strings.Secrets)) * 10


	for _, ioc := range result.IOCs {
		if ioc.Type == "ip" {
			score += 5
		}
	}


	if result.Meta.Packed {
		score += 15
	}

	score = math.Min(score, 100)
	result.Score.Overall = score

	switch {
	case score >= 75:
		result.Score.RiskLevel = "critical"
		result.Score.RiskLabel = "CRITICAL RISK"
	case score >= 50:
		result.Score.RiskLevel = "high"
		result.Score.RiskLabel = "HIGH RISK"
	case score >= 25:
		result.Score.RiskLevel = "medium"
		result.Score.RiskLabel = "MEDIUM RISK"
	default:
		result.Score.RiskLevel = "low"
		result.Score.RiskLabel = "LOW RISK"
	}
}



func extractPrintable(data []byte, minLen int) []string {
	var results []string
	var cur []byte
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			cur = append(cur, b)
		} else {
			if len(cur) >= minLen {
				s := strings.TrimSpace(string(cur))
				if len(s) >= minLen {
					results = append(results, s)
				}
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= minLen {
		results = append(results, strings.TrimSpace(string(cur)))
	}
	return results
}

func computeEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPrivateIP(ip string) bool {
	private := []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.",
		"172.19.", "172.20.", "172.31.", "127.", "0.0.0.0"}
	for _, p := range private {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *ScanResult) ToJSON() string {
	d, _ := json.MarshalIndent(r, "", "  ")
	return string(d)
}
