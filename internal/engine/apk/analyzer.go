package apk

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)



type ScanResult struct {
	Meta        Meta
	Permissions []Permission
	Certificate *Certificate
	Strings     StringAnalysis
	IOCs        []IOC
	Findings    []Finding
	Score       Score
	FilePath    string
}

type Meta struct {
	FileName    string
	PackageName string
	VersionName string
	VersionCode int
	MinSDK      int
	TargetSDK   int
	FileSize    int64
	MD5         string
	SHA1        string
	SHA256      string
	FileType    string
	NativeLibs  []string
	Activities  []string
	Services    []string
	Receivers   []string
	Providers   []string
	DeepLinks   []string
}

type Permission struct {
	Name        string
	Protection  string
	Dangerous   bool
	Description string
}

type Certificate struct {
	Subject    string
	Issuer     string
	NotBefore  string
	NotAfter   string
	Algorithm  string
	Fingerprint string
	SelfSigned bool
	Expired    bool
	KeySize    int
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
	Severity    string // critical, high, medium, low, info
	Category    string
	Remediation string
	CWE         string
}

type Score struct {
	Overall     float64 // 0–100 (higher = riskier)
	RiskLevel   string  // critical, high, medium, low
	RiskLabel   string
	Breakdown   map[string]float64
}



var dangerousPerms = map[string]string{
	"android.permission.READ_CONTACTS":              "Reads user contacts",
	"android.permission.WRITE_CONTACTS":             "Modifies user contacts",
	"android.permission.READ_CALL_LOG":              "Reads call history",
	"android.permission.WRITE_CALL_LOG":             "Modifies call history",
	"android.permission.PROCESS_OUTGOING_CALLS":     "Intercepts outgoing calls",
	"android.permission.READ_SMS":                   "Reads SMS messages",
	"android.permission.RECEIVE_SMS":                "Receives SMS messages",
	"android.permission.SEND_SMS":                   "Sends SMS messages",
	"android.permission.RECEIVE_MMS":                "Receives MMS messages",
	"android.permission.READ_EXTERNAL_STORAGE":      "Reads device storage",
	"android.permission.WRITE_EXTERNAL_STORAGE":     "Writes to device storage",
	"android.permission.MANAGE_EXTERNAL_STORAGE":    "Full storage access",
	"android.permission.CAMERA":                     "Access device camera",
	"android.permission.RECORD_AUDIO":               "Record microphone audio",
	"android.permission.ACCESS_FINE_LOCATION":       "Precise GPS location",
	"android.permission.ACCESS_COARSE_LOCATION":     "Approximate location",
	"android.permission.ACCESS_BACKGROUND_LOCATION": "Background location tracking",
	"android.permission.READ_PHONE_STATE":           "Reads device identifiers",
	"android.permission.CALL_PHONE":                 "Makes phone calls",
	"android.permission.USE_BIOMETRIC":              "Uses biometric auth",
	"android.permission.INSTALL_PACKAGES":           "Installs other APKs",
	"android.permission.DELETE_PACKAGES":            "Uninstalls packages",
	"android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service binding",
	"android.permission.BIND_DEVICE_ADMIN":          "Device admin binding",
	"android.permission.SYSTEM_ALERT_WINDOW":        "Overlay on other apps",
	"android.permission.WRITE_SETTINGS":             "Modifies system settings",
	"android.permission.GET_ACCOUNTS":               "Access account list",
	"android.permission.USE_CREDENTIALS":            "Use account credentials",
}



var (
	urlRe      = regexp.MustCompile(`https?://[a-zA-Z0-9.\-_/?=&#%+@:]{8,}`)
	ipRe       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	emailRe    = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	domainRe   = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|app|dev|xyz|info|biz|online|site)`)
	apiRe      = regexp.MustCompile(`(?i)/(?:api|v\d|rest|graphql|endpoint)/[a-zA-Z0-9/_\-]+`)
	awsKeyRe   = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	googleKeyRe = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	githubRe   = regexp.MustCompile(`gh[ps]_[A-Za-z0-9]{36,}`)
	jwtRe      = regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*`)
	privateKeyRe = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`)
	b64Re      = regexp.MustCompile(`(?:[A-Za-z0-9+/]{40,}={0,2})`)
)

type antiAnalysisPattern struct {
	Pattern  *regexp.Regexp
	Category string
	Severity string
}

var antiPatterns = []antiAnalysisPattern{
	{regexp.MustCompile(`isDebuggerConnected|Debug\.isDebuggerConnected`), "Anti-Debug", "high"},
	{regexp.MustCompile(`TracerPid|ptrace|android\.os\.Debug`), "Anti-Debug", "high"},
	{regexp.MustCompile(`isEmulator|checkEmulator|detectEmulator`), "Anti-Emulator", "high"},
	{regexp.MustCompile(`Build\.FINGERPRINT.*generic|goldfish|vbox|genymotion`), "Anti-Emulator", "high"},
	{regexp.MustCompile(`/system/bin/su|/sbin/su|which su`), "Root Detection", "medium"},
	{regexp.MustCompile(`RootBeer|isRooted|checkRoot|detectRoot`), "Root Detection", "medium"},
	{regexp.MustCompile(`DexClassLoader|PathClassLoader|loadDex`), "Dynamic Loading", "high"},
	{regexp.MustCompile(`Runtime\.exec|ProcessBuilder`), "Command Exec", "critical"},
	{regexp.MustCompile(`getDeviceId|getSubscriberId|getSimSerialNumber`), "Device ID Harvest", "high"},
	{regexp.MustCompile(`TelephonyManager.*getLine1Number`), "Phone Number Harvest", "high"},
	{regexp.MustCompile(`onAccessibilityEvent|AccessibilityService`), "Accessibility Abuse", "critical"},
	{regexp.MustCompile(`captureScreen|screenshot|screenCapture`), "Screen Capture", "critical"},
	{regexp.MustCompile(`android\.intent\.action\.BOOT_COMPLETED`), "Boot Persistence", "high"},
	{regexp.MustCompile(`KeyLogger|recordKey|onKeyEvent`), "Keylogging Indicator", "critical"},
	{regexp.MustCompile(`Cipher\.getInstance|SecretKeySpec|AESCrypt`), "Crypto Usage", "medium"},
	{regexp.MustCompile(`HttpURLConnection|OkHttpClient|Retrofit`), "Network Activity", "info"},
	{regexp.MustCompile(`WebView.*javascript|loadUrl.*javascript:`), "JS Injection Risk", "high"},
	{regexp.MustCompile(`getExternalStorageDirectory|Environment\.DIRECTORY`), "File System Access", "medium"},
}



type Analyzer struct{}

func NewAnalyzer() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Scan(apkPath string) (*ScanResult, error) {
	info, err := os.Stat(apkPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access file: %w", err)
	}

	result := &ScanResult{
		FilePath: apkPath,
		Meta: Meta{
			FileName: filepath.Base(apkPath),
			FileSize: info.Size(),
			FileType: "Android APK",
		},
		Score: Score{Breakdown: make(map[string]float64)},
	}


	if err := computeHashes(apkPath, &result.Meta); err != nil {
		return nil, err
	}


	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("invalid APK (not a valid ZIP): %w", err)
	}
	defer r.Close()


	var allStrings []string

	for _, f := range r.File {
		switch {
		case f.Name == "AndroidManifest.xml":
			a.parseManifestFile(f, result)

		case strings.HasSuffix(f.Name, ".dex"):
			strs := extractFromDex(f)
			allStrings = append(allStrings, strs...)

		case strings.HasSuffix(f.Name, ".so"):
			result.Meta.NativeLibs = append(result.Meta.NativeLibs,
				filepath.Base(f.Name))

		case strings.HasPrefix(f.Name, "META-INF/") && strings.HasSuffix(f.Name, ".RSA"):

			result.Certificate = &Certificate{
				Subject:    "Parsed from " + f.Name,
				Issuer:     "See full analysis",
				Algorithm:  "RSA",
				SelfSigned: true,
			}
		}
	}


	a.analyzeStrings(allStrings, result)


	a.generateFindings(result)


	a.computeScore(result)

	return result, nil
}



func (a *Analyzer) parseManifestFile(f *zip.File, result *ScanResult) {
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return
	}


	strs := extractPrintable(data, 5)
	for _, s := range strs {
		s = strings.TrimSpace(s)
		switch {
		case strings.HasPrefix(s, "android.permission.") ||
			strings.HasPrefix(s, "com.android.") ||
			strings.Contains(s, ".permission."):
			perm := Permission{Name: s}
			if desc, ok := dangerousPerms[s]; ok {
				perm.Dangerous = true
				perm.Protection = "dangerous"
				perm.Description = desc
			} else {
				perm.Protection = "normal"
			}
			result.Permissions = append(result.Permissions, perm)

		case strings.Contains(s, "://") && len(s) < 100:

			result.Meta.DeepLinks = append(result.Meta.DeepLinks, s)

		case looksLikeClass(s):

			lower := strings.ToLower(s)
			switch {
			case strings.Contains(lower, "activity"):
				result.Meta.Activities = append(result.Meta.Activities, s)
			case strings.Contains(lower, "service"):
				result.Meta.Services = append(result.Meta.Services, s)
			case strings.Contains(lower, "receiver"):
				result.Meta.Receivers = append(result.Meta.Receivers, s)
			case strings.Contains(lower, "provider"):
				result.Meta.Providers = append(result.Meta.Providers, s)
			}
		}


		if result.Meta.PackageName == "" && looksLikePackage(s) {
			result.Meta.PackageName = s
		}
	}
}



func (a *Analyzer) analyzeStrings(strs []string, result *ScanResult) {
	combined := strings.Join(strs, "\n")
	result.Strings.Total = len(strs)

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


	for _, d := range domainRe.FindAllString(combined, -1) {
		if len(d) > 6 && !strings.Contains(d, "android") && !strings.Contains(d, "google") {
			add(&result.Strings.Domains, d)
		}
	}


	for _, ep := range apiRe.FindAllString(combined, -1) {
		add(&result.Strings.Endpoints, ep)
	}


	secretChecks := []struct {
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
	for _, sc := range secretChecks {
		for _, match := range sc.Re.FindAllString(combined, -1) {
			result.Strings.Secrets = append(result.Strings.Secrets, SuspiciousString{
				Value:    redact(match),
				Category: sc.Category,
				Severity: sc.Severity,
			})
			result.IOCs = append(result.IOCs, IOC{
				Type:     "secret",
				Value:    redact(match),
				Context:  sc.Category,
				Severity: sc.Severity,
			})
		}
	}


	for _, str := range strs {
		for _, pat := range antiPatterns {
			if pat.Pattern.MatchString(str) {
				result.Strings.Secrets = append(result.Strings.Secrets, SuspiciousString{
					Value:    truncStr(str, 80),
					Category: pat.Category,
					Severity: pat.Severity,
				})
				break
			}
		}
	}
}



func (a *Analyzer) generateFindings(result *ScanResult) {
	fid := 1
	next := func() string {
		id := fmt.Sprintf("KIT-%04d", fid)
		fid++
		return id
	}

	dangerousCount := 0
	for _, p := range result.Permissions {
		if p.Dangerous {
			dangerousCount++
		}
	}

	if dangerousCount > 0 {
		sev := "medium"
		if dangerousCount >= 8 {
			sev = "critical"
		} else if dangerousCount >= 5 {
			sev = "high"
		}
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       fmt.Sprintf("Dangerous Permissions Declared (%d)", dangerousCount),
			Description: fmt.Sprintf("Application requests %d dangerous permission(s) that can access sensitive device resources including contacts, location, camera, microphone, and SMS.", dangerousCount),
			Severity:    sev,
			Category:    "permissions",
			CWE:         "CWE-272",
			Remediation: "Apply principle of least privilege. Remove permissions not strictly required for core functionality. Justify each dangerous permission in privacy policy.",
		})
	}

	if len(result.Strings.Secrets) > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       fmt.Sprintf("Hardcoded Credentials/Secrets Detected (%d)", len(result.Strings.Secrets)),
			Description: "API keys, tokens, or credentials found embedded in the APK binary. These can be extracted by anyone who decompiles the APK.",
			Severity:    "critical",
			Category:    "secrets",
			CWE:         "CWE-798",
			Remediation: "Never embed secrets in APK binaries. Use server-side authentication, Android Keystore, or secure remote config.",
		})
	}


	antiDebug := 0
	for _, s := range result.Strings.Secrets {
		if strings.Contains(s.Category, "Anti-Debug") || strings.Contains(s.Category, "Anti-Emulator") {
			antiDebug++
		}
	}
	if antiDebug > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       "Anti-Analysis Techniques Detected",
			Description: "Code detected that checks for debuggers, emulators, or analysis environments. Legitimate apps rarely employ these techniques.",
			Severity:    "high",
			Category:    "anti_analysis",
			CWE:         "CWE-1254",
			Remediation: "Investigate the purpose of anti-analysis code. Legitimate security checks should be documented and transparent.",
		})
	}

	if len(result.Meta.NativeLibs) > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       fmt.Sprintf("Native Libraries Present (%d)", len(result.Meta.NativeLibs)),
			Description: "The APK contains native (.so) libraries. These are harder to analyze and may contain obfuscated or malicious code.",
			Severity:    "medium",
			Category:    "native_code",
			CWE:         "CWE-829",
			Remediation: "Audit native libraries for known vulnerabilities. Verify library sources and checksums.",
		})
	}

	if len(result.Meta.DeepLinks) > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       fmt.Sprintf("Deep Links Registered (%d)", len(result.Meta.DeepLinks)),
			Description: "Application registers URI schemes that can be triggered by other apps or websites.",
			Severity:    "low",
			Category:    "deep_links",
			CWE:         "CWE-601",
			Remediation: "Validate all data received via deep links. Implement intent validation and authentication for sensitive deep link actions.",
		})
	}

	if len(result.Strings.URLs) > 20 {
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       fmt.Sprintf("High Number of Embedded URLs (%d)", len(result.Strings.URLs)),
			Description: "Large number of embedded URLs may indicate C2 communication endpoints, advertising SDKs, or data exfiltration targets.",
			Severity:    "medium",
			Category:    "network",
			CWE:         "CWE-200",
			Remediation: "Review all embedded URLs. Remove or document legitimate endpoints. Consider certificate pinning for sensitive communications.",
		})
	}

	if result.Certificate != nil && result.Certificate.SelfSigned {
		result.Findings = append(result.Findings, Finding{
			ID:          next(),
			Title:       "APK Signed with Self-Signed/Debug Certificate",
			Description: "The APK is signed with a self-signed certificate. Production apps should use a private certificate issued by the developer.",
			Severity:    "medium",
			Category:    "certificate",
			CWE:         "CWE-295",
			Remediation: "Sign release builds with a properly managed private key. Store the keystore securely offline.",
		})
	}
}



func (a *Analyzer) computeScore(result *ScanResult) {
	score := 0.0


	dangerCount := 0
	for _, p := range result.Permissions {
		if p.Dangerous {
			dangerCount++
		}
	}
	permScore := math.Min(float64(dangerCount)*4, 30)
	score += permScore
	result.Score.Breakdown["permissions"] = permScore


	findScore := 0.0
	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			findScore += 20
		case "high":
			findScore += 12
		case "medium":
			findScore += 6
		case "low":
			findScore += 2
		}
	}
	findScore = math.Min(findScore, 50)
	score += findScore
	result.Score.Breakdown["findings"] = findScore


	iocScore := math.Min(float64(len(result.IOCs))*1.5, 15)
	score += iocScore
	result.Score.Breakdown["iocs"] = iocScore


	nativeScore := math.Min(float64(len(result.Meta.NativeLibs))*2, 5)
	score += nativeScore
	result.Score.Breakdown["native_libs"] = nativeScore

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



func computeHashes(path string, meta *Meta) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h1 := md5.New()
	h2 := sha1.New()
	h3 := sha256.New()
	w := io.MultiWriter(h1, h2, h3)
	if _, err := io.Copy(w, f); err != nil {
		return err
	}
	meta.MD5 = fmt.Sprintf("%x", h1.Sum(nil))
	meta.SHA1 = fmt.Sprintf("%x", h2.Sum(nil))
	meta.SHA256 = fmt.Sprintf("%x", h3.Sum(nil))
	return nil
}

func extractFromDex(f *zip.File) []string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil
	}
	return extractPrintable(data, 5)
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
		results = append(results, string(cur))
	}
	return results
}

func looksLikeClass(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		for _, r := range p {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
				return false
			}
		}
	}
	return true
}

func looksLikePackage(s string) bool {
	if !looksLikeClass(s) {
		return false
	}
	parts := strings.Split(s, ".")
	return len(parts) >= 2 && len(s) >= 5 && len(s) <= 100 &&
		!strings.Contains(s, "android") && !strings.Contains(s, "java")
}

func isPrivateIP(ip string) bool {
	private := []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.",
		"172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
		"172.31.", "127.", "0.0.0.0", "::1", "fe80:"}
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
