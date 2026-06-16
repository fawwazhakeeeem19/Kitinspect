package output

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	fileengine "github.com/kitinspect/kitinspect/internal/engine/file"
)


const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	FgRed   = "\033[31m"
	FgGreen = "\033[32m"
	FgYellow = "\033[33m"
	FgCyan  = "\033[36m"
	FgWhite = "\033[37m"
	FgBrightRed    = "\033[91m"
	FgBrightGreen  = "\033[92m"
	FgBrightYellow = "\033[93m"
	FgBrightCyan   = "\033[96m"
	FgBrightWhite  = "\033[97m"
)

var noColor bool

func init() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		noColor = true
	}
}

func c(code, text string) string {
	if noColor {
		return text
	}
	return code + text + Reset
}

func PrintBanner() {
	banner := `
  ██╗  ██╗██╗████████╗██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗
  ██║ ██╔╝██║╚══██╔══╝██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝
  █████╔╝ ██║   ██║   ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║
  ██╔═██╗ ██║   ██║   ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║
  ██║  ██╗██║   ██║   ██║██║ ╚████║███████║██║      ███████╗╚██████╗   ██║
  ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝      ╚══════╝ ╚═════╝   ╚═╝`
	fmt.Println(c(FgBrightCyan+Bold, banner))
	fmt.Printf("  %s  %s\n\n",
		c(FgBrightWhite+Bold, "Professional Security Analysis Platform"),
		c(Dim+FgWhite, "v1.1.0 · Defensive analysis only"),
	)
}

func Section(title string) {
	width := 68
	bar := strings.Repeat("─", width-len(title)-4)
	fmt.Printf("\n  %s %s %s\n",
		c(FgBrightCyan, "┌─"),
		c(Bold+FgBrightWhite, title),
		c(FgBrightCyan, bar),
	)
}

func SectionEnd() {
	fmt.Printf("  %s\n", c(FgBrightCyan, "└"+strings.Repeat("─", 66)))
}

func kv(label, value string) {
	fmt.Printf("  %s %-22s %s\n",
		c(FgBrightCyan, "│"),
		c(Dim+FgWhite, label+":"),
		c(FgBrightWhite, value),
	)
}

func kvColored(label, value, color string) {
	fmt.Printf("  %s %-22s %s\n",
		c(FgBrightCyan, "│"),
		c(Dim+FgWhite, label+":"),
		c(color, value),
	)
}

func SeverityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return FgBrightRed + Bold
	case "high":
		return FgRed
	case "medium":
		return FgYellow
	case "low":
		return FgBrightCyan
	default:
		return FgWhite
	}
}

func SeverityBadge(sev string) string {
	labels := map[string]string{
		"critical": "CRITICAL",
		"high":     "HIGH    ",
		"medium":   "MEDIUM  ",
		"low":      "LOW     ",
		"info":     "INFO    ",
	}
	label := labels[strings.ToLower(sev)]
	if label == "" {
		label = strings.ToUpper(sev)
	}
	return c(SeverityColor(sev), "["+strings.TrimRight(label, " ")+"]")
}

func RiskBadge(level string) string {
	colors := map[string]string{
		"critical": FgBrightRed + Bold,
		"high":     FgRed + Bold,
		"medium":   FgYellow + Bold,
		"low":      FgBrightGreen + Bold,
	}
	col := colors[level]
	if col == "" {
		col = FgWhite
	}
	return c(col, "[ "+strings.ToUpper(level)+" RISK ]")
}

func PrintScoreGauge(score float64, level string) {
	width := 40
	filled := int(math.Round(score / 100 * float64(width)))
	empty := width - filled
	color := SeverityColor(level)
	bar := c(color, strings.Repeat("█", filled)) + c(Dim+FgWhite, strings.Repeat("░", empty))

	Section("SECURITY SCORE")
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	fmt.Printf("  %s  %s  %s%s\n",
		c(FgBrightCyan, "│"),
		bar,
		c(color+Bold, fmt.Sprintf(" %.0f/100 ", score)),
		RiskBadge(level),
	)
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	SectionEnd()
}



func PrintFileMeta(meta *fileengine.FileMeta) {
	Section("FILE METADATA")
	kv("File", meta.FileName)
	kv("File Type", meta.FileType)
	kv("File Size", formatSize(meta.FileSize))
	kv("Magic Bytes", strOrDash(meta.MagicBytes))
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	kv("MD5", meta.MD5)
	kv("SHA1", meta.SHA1)
	kv("SHA256", meta.SHA256)
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	kv("Entropy", fmt.Sprintf("%.4f / 8.0", meta.Entropy))
	if meta.Packed {
		kvColored("Packed/Encrypted", "YES — High entropy detected", FgYellow)
	} else {
		kvColored("Packed/Encrypted", "No", FgGreen)
	}
	if len(meta.Sections) > 0 {
		fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
		kv("Contents", fmt.Sprintf("%d entries", len(meta.Sections)))
	}
	SectionEnd()
}


func PrintFileStrings(strs *fileengine.StringAnalysis, verbose bool) {
	Section("STRING ANALYSIS")
	fmt.Printf("  %s  Strings extracted: %s\n",
		c(FgBrightCyan, "│"),
		c(FgBrightWhite, fmt.Sprintf("%d", strs.Total)),
	)
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))

	if len(strs.URLs) > 0 {
		fmt.Printf("  %s  %s (%d)\n", c(FgBrightCyan, "│"), c(FgBrightCyan+Bold, "▸ EMBEDDED URLs"), len(strs.URLs))
		lim := len(strs.URLs)
		if !verbose && lim > 8 {
			lim = 8
		}
		for _, u := range strs.URLs[:lim] {
			fmt.Printf("  %s    %s %s\n", c(FgBrightCyan, "│"), c(FgCyan, "·"), c(FgWhite, truncStr(u, 70)))
		}
		if !verbose && len(strs.URLs) > 8 {
			fmt.Printf("  %s    %s\n", c(FgBrightCyan, "│"),
				c(Dim+FgWhite, fmt.Sprintf("... and %d more (use --verbose)", len(strs.URLs)-8)))
		}
		fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	}

	if len(strs.IPs) > 0 {
		fmt.Printf("  %s  %s (%d)\n", c(FgBrightCyan, "│"), c(FgYellow+Bold, "▸ IP ADDRESSES"), len(strs.IPs))
		for _, ip := range strs.IPs {
			fmt.Printf("  %s    %s %s\n", c(FgBrightCyan, "│"), c(FgYellow, "◈"), c(FgBrightWhite, ip))
		}
		fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	}

	if len(strs.Endpoints) > 0 {
		fmt.Printf("  %s  %s (%d)\n", c(FgBrightCyan, "│"), c(FgBrightCyan+Bold, "▸ API ENDPOINTS"), len(strs.Endpoints))
		for _, ep := range strs.Endpoints {
			fmt.Printf("  %s    %s %s\n", c(FgBrightCyan, "│"), c(FgCyan, "→"), c(FgWhite, ep))
		}
		fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	}

	if len(strs.Secrets) > 0 {
		fmt.Printf("  %s  %s (%d)\n", c(FgBrightCyan, "│"), c(FgBrightRed+Bold, "▸ SUSPICIOUS PATTERNS"), len(strs.Secrets))
		for _, s := range strs.Secrets {
			badge := SeverityBadge(s.Severity)
			fmt.Printf("  %s    %s %-22s %s\n",
				c(FgBrightCyan, "│"),
				badge,
				c(FgYellow, s.Category),
				c(Dim+FgWhite, s.Value),
			)
		}
	}
	SectionEnd()
}



func PrintFileIOCs(iocs []fileengine.IOC) {
	Section("INDICATORS OF COMPROMISE")
	if len(iocs) == 0 {
		fmt.Printf("  %s  %s\n", c(FgBrightCyan, "│"), c(FgGreen, "No IOCs detected"))
		SectionEnd()
		return
	}

	groups := make(map[string][]fileengine.IOC)
	order := []string{"secret", "ip", "url", "domain", "email"}
	for _, ioc := range iocs {
		groups[ioc.Type] = append(groups[ioc.Type], ioc)
	}

	for _, t := range order {
		items, ok := groups[t]
		if !ok {
			continue
		}
		fmt.Printf("  %s  %s (%d)\n",
			c(FgBrightCyan, "│"),
			c(FgBrightWhite+Bold, "▸ "+strings.ToUpper(t)+"s"),
			len(items),
		)
		for _, ioc := range items {
			badge := SeverityBadge(ioc.Severity)
			ctx := ""
			if ioc.Context != "" {
				ctx = " (" + ioc.Context + ")"
			}
			fmt.Printf("  %s    %s %s%s\n",
				c(FgBrightCyan, "│"),
				badge,
				c(FgWhite, truncStr(ioc.Value, 60)),
				c(Dim+FgWhite, ctx),
			)
		}
		fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	}
	SectionEnd()
}



func PrintFileFindings(findings []fileengine.Finding) {
	Section("SECURITY FINDINGS")
	if len(findings) == 0 {
		fmt.Printf("  %s  %s\n", c(FgBrightCyan, "│"), c(FgGreen, "No security findings"))
		SectionEnd()
		return
	}

	sev := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	sorted := make([]fileengine.Finding, len(findings))
	copy(sorted, findings)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sev[sorted[j].Severity] > sev[sorted[i].Severity] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	for i, f := range sorted {
		if i > 0 {
			fmt.Printf("  %s  %s\n", c(FgBrightCyan, "│"), c(Dim+FgWhite, "·  ·  ·"))
		}
		badge := SeverityBadge(f.Severity)
		fmt.Printf("  %s  %s %s  %s\n",
			c(FgBrightCyan, "│"),
			badge,
			c(FgBrightWhite+Bold, f.ID),
			c(FgBrightWhite, f.Title),
		)
		fmt.Printf("  %s       %s\n",
			c(FgBrightCyan, "│"),
			c(FgWhite, wordWrap(f.Description, 68)),
		)
		if f.Remediation != "" {
			fmt.Printf("  %s  %s %s\n",
				c(FgBrightCyan, "│"),
				c(FgGreen, "  Fix:"),
				c(Dim+FgWhite, f.Remediation),
			)
		}
	}
	SectionEnd()
}



func PrintFileSummary(result *fileengine.ScanResult) {
	Section("SCAN SUMMARY")
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	row := func(label, val, col string) {
		fmt.Printf("  %s   %-28s  %s\n",
			c(FgBrightCyan, "│"),
			c(Dim+FgWhite, label),
			c(col, val),
		)
	}

	row("Target File:", result.Meta.FileName, FgBrightWhite)
	row("File Type:", result.Meta.FileType, FgBrightWhite)
	row("Scan Time:", time.Now().Format("2006-01-02 15:04:05"), FgWhite)
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	row("Total IOCs:", fmt.Sprintf("%d", len(result.IOCs)), FgYellow)
	row("Embedded URLs:", fmt.Sprintf("%d", len(result.Strings.URLs)), FgWhite)
	row("Suspicious Patterns:", fmt.Sprintf("%d", len(result.Strings.Secrets)), FgWhite)

	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	for _, sv := range []string{"critical", "high", "medium", "low"} {
		n := counts[sv]
		if n > 0 {
			row(fmt.Sprintf("  %s Findings:", strings.Title(sv)),
				fmt.Sprintf("%d", n),
				SeverityColor(sv),
			)
		}
	}
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	scoreColor := SeverityColor(result.Score.RiskLevel)
	row("Risk Score:", fmt.Sprintf("%.1f / 100  %s", result.Score.Overall, RiskBadge(result.Score.RiskLevel)), scoreColor)
	fmt.Printf("  %s\n", c(FgBrightCyan, "│"))
	SectionEnd()
}



func Spinner(msg string) func() {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan struct{})
	go func() {
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r  %s  %s\n", c(FgGreen, "✔"), c(FgWhite, msg+" done"))
				return
			default:
				fmt.Printf("\r  %s  %s", c(FgBrightCyan, frames[i%len(frames)]), c(FgWhite, msg+"..."))
				time.Sleep(80 * time.Millisecond)
				i++
			}
		}
	}()
	return func() { done <- struct{}{}; time.Sleep(10 * time.Millisecond) }
}

func Success(msg string) {
	fmt.Printf("  %s  %s\n", c(FgGreen, "✔"), c(FgBrightGreen, msg))
}

func Error(msg string) {
	fmt.Printf("  %s  %s\n", c(FgBrightRed, "✖"), c(FgBrightRed, msg))
}

func PrintJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}



func formatSize(bytes int64) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%.2f MB (%d bytes)", float64(bytes)/float64(1<<20), bytes)
	case bytes >= 1<<10:
		return fmt.Sprintf("%.2f KB (%d bytes)", float64(bytes)/float64(1<<10), bytes)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

func strOrDash(s string) string {
	if s == "" {
		return c(Dim+FgWhite, "—")
	}
	return s
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func wordWrap(text string, width int) string {
	if len(text) <= width {
		return text
	}
	var lines []string
	for len(text) > width {
		i := strings.LastIndex(text[:width], " ")
		if i < 0 {
			i = width
		}
		lines = append(lines, text[:i])
		text = text[i+1:]
	}
	lines = append(lines, text)
	return strings.Join(lines, "\n  │       ")
}
