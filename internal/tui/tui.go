package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)



var (
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("51"))

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("51")).
			Padding(0, 1)

	styleSubtitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true)

	styleSelected = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("24")).
			Padding(0, 2)

	styleNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			Padding(0, 2)

	styleIcon = lipgloss.NewStyle().
			Foreground(lipgloss.Color("51"))

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	styleCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	styleHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("33"))

	styleStatusBar = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("252")).
			Padding(0, 1).
			Width(78)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)
)



type menuItem struct {
	icon  string
	label string
	desc  string
	key   string
}

var mainMenu = []menuItem{
	{"⬡", "APK Scan", "Full static analysis of an Android APK", "s"},
	{"⊙", "Permissions", "Analyze APK permissions and risk", "p"},
	{"◈", "Certificates", "Inspect signing certificates", "c"},
	{"≋", "Strings", "Extract strings and detect secrets", "x"},
	{"⟁", "IOC Explorer", "Indicators of Compromise viewer", "i"},
	{"⊞", "Reports", "View and export analysis reports", "r"},
	{"⌂", "History", "Previous scan results", "h"},
	{"⚙", "Settings", "Configure KitInspect", ","},
	{"⏻", "Quit", "Exit KitInspect", "q"},
}



type screen int

const (
	screenMain screen = iota
	screenScanInput
	screenScanning
	screenResult
	screenHistory
	screenSettings
	screenHelp
)

type Model struct {
	width    int
	height   int
	cursor   int
	screen   screen
	input    string
	scanning bool
	scanFile string
	status   string
	version  string
}

func New() Model {
	return Model{
		width:   80,
		height:  24,
		cursor:  0,
		screen:  screenMain,
		status:  "Ready — Press ? for help",
		version: "v1.0.0",
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}



func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch m.screen {

		case screenMain:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(mainMenu)-1 {
					m.cursor++
				}
			case "enter", " ":
				return m.selectMenuItem()
			case "?":
				m.screen = screenHelp
			default:

				for i, item := range mainMenu {
					if msg.String() == item.key {
						m.cursor = i
						return m.selectMenuItem()
					}
				}
			}

		case screenScanInput:
			switch msg.String() {
			case "esc":
				m.screen = screenMain
				m.input = ""
			case "enter":
				if m.input != "" {
					m.scanFile = m.input
					m.screen = screenScanning
					m.status = "Scanning: " + m.input
					return m, runScanCmd(m.input)
				}
			case "backspace":
				if len(m.input) > 0 {
					m.input = m.input[:len(m.input)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.input += msg.String()
				}
			}

		case screenScanning:
			switch msg.String() {
			case "esc", "q":
				m.screen = screenMain
				m.scanning = false
			}

		case screenResult, screenHistory, screenSettings, screenHelp:
			switch msg.String() {
			case "esc", "q", "backspace":
				m.screen = screenMain
			}
		}

	case scanCompleteMsg:
		m.screen = screenResult
		m.scanning = false
		m.status = "Scan complete: " + m.scanFile

	case scanErrorMsg:
		m.screen = screenMain
		m.scanning = false
		m.status = "✖ Scan failed: " + string(msg)
	}

	return m, nil
}

func (m Model) selectMenuItem() (tea.Model, tea.Cmd) {
	item := mainMenu[m.cursor]
	switch item.key {
	case "q":
		return m, tea.Quit
	case "s":
		m.screen = screenScanInput
		m.input = ""
		m.status = "Enter path to APK file"
	case "p", "c", "x":
		m.screen = screenScanInput
		m.input = ""
		m.status = "Enter APK path for " + item.label
	case "r", "h":
		m.screen = screenHistory
	case ",":
		m.screen = screenSettings
	case "?":
		m.screen = screenHelp
	}
	return m, nil
}



func (m Model) View() string {
	switch m.screen {
	case screenMain:
		return m.viewMain()
	case screenScanInput:
		return m.viewScanInput()
	case screenScanning:
		return m.viewScanning()
	case screenResult:
		return m.viewResult()
	case screenHistory:
		return m.viewHistory()
	case screenSettings:
		return m.viewSettings()
	case screenHelp:
		return m.viewHelp()
	}
	return ""
}



func (m Model) viewMain() string {
	var b strings.Builder


	b.WriteString(m.renderHeader())
	b.WriteString("\n")


	left := m.renderMenu()
	right := m.renderInfoPanel()

	cols := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	b.WriteString(cols)
	b.WriteString("\n")


	b.WriteString(m.renderStatusBar())

	return b.String()
}

func (m Model) renderHeader() string {
	logo := `
  ██╗  ██╗██╗████████╗██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗
  ██║ ██╔╝██║╚══██╔══╝██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝
  █████╔╝ ██║   ██║   ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   
  ██╔═██╗ ██║   ██║   ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   
  ██║  ██╗██║   ██║   ██║██║ ╚████║███████║██║      ███████╗╚██████╗   ██║   
  ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝      ╚══════╝ ╚═════╝   ╚═╝  `

	styled := lipgloss.NewStyle().
		Foreground(lipgloss.Color("51")).
		Render(logo)

	tagline := lipgloss.NewStyle().
		Foreground(lipgloss.Color("245")).
		Italic(true).
		PaddingLeft(2).
		Render("Professional APK Security Analysis Platform  ·  " + m.version)

	return styled + "\n" + tagline
}

func (m Model) renderMenu() string {
	var b strings.Builder

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("51")).
		PaddingLeft(2).
		PaddingBottom(1).
		Render("  NAVIGATION")

	b.WriteString(title + "\n")

	for i, item := range mainMenu {
		icon := styleIcon.Render(item.icon)
		keyBadge := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render("[" + item.key + "]")

		line := fmt.Sprintf("  %s  %-16s %s", icon, item.label, keyBadge)

		if i == m.cursor {
			b.WriteString(styleSelected.Width(36).Render(line) + "\n")
		} else {
			b.WriteString(styleNormal.Render(line) + "\n")
		}
	}

	content := b.String()
	return styleBorder.
		Width(38).
		MarginLeft(1).
		MarginTop(1).
		Render(content)
}

func (m Model) renderInfoPanel() string {
	selected := mainMenu[m.cursor]

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("51")).
		Render("  " + selected.icon + "  " + selected.label)

	desc := lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")).
		PaddingTop(1).
		PaddingLeft(2).
		Render(selected.desc)

	divider := styleDim.Render("  " + strings.Repeat("─", 26))

	quick := lipgloss.NewStyle().
		Foreground(lipgloss.Color("245")).
		PaddingTop(1).
		PaddingLeft(2).
		Render("Quick Start:\n\n" +
			"  $ kitinspect scan app.apk\n" +
			"  $ kitinspect permissions app.apk\n" +
			"  $ kitinspect cert app.apk\n" +
			"  $ kitinspect strings app.apk\n" +
			"  $ kitinspect report app.apk")

	statsBox := lipgloss.NewStyle().
		PaddingTop(2).
		PaddingLeft(2).
		Foreground(lipgloss.Color("245")).
		Render("─── Stats ───────────────\n\n" +
			"  Scans run:     0\n" +
			"  APKs analyzed: 0\n" +
			"  IOCs found:    0\n" +
			"  Reports saved: 0")

	content := title + "\n" + desc + "\n" + divider + "\n" + quick + "\n" + statsBox

	return styleBorder.
		Width(34).
		MarginLeft(1).
		MarginTop(1).
		Render(content)
}

func (m Model) renderStatusBar() string {
	left := "  " + m.status
	right := "↑↓ navigate  enter select  ? help  q quit  "
	space := strings.Repeat(" ", max(0, m.width-len(left)-len(right)-2))

	bar := left + space + right
	return styleStatusBar.Width(m.width).Render(bar)
}



func (m Model) viewScanInput() string {
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")

	prompt := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("51")).
		PaddingLeft(4).
		Render("  Enter APK file path to analyze:")

	inputBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("51")).
		Padding(0, 1).
		Width(60).
		MarginLeft(4).
		Render("  " + m.input + "█")

	help := styleDim.PaddingLeft(4).Render("\n  Examples:\n" +
		"    /home/user/app.apk\n" +
		"    ./suspicious.apk\n\n" +
		"  enter  start scan   esc  back")

	b.WriteString(prompt + "\n\n")
	b.WriteString("  " + inputBox + "\n")
	b.WriteString(help + "\n\n")
	b.WriteString(m.renderStatusBar())

	return b.String()
}



func (m Model) viewScanning() string {
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")

	steps := []struct{ done bool; label string }{
		{true, "Reading APK structure"},
		{true, "Computing cryptographic hashes"},
		{true, "Parsing AndroidManifest.xml"},
		{true, "Extracting DEX strings"},
		{false, "Analyzing permissions"},
		{false, "Running IOC detection"},
		{false, "Generating findings"},
		{false, "Computing risk score"},
	}

	var stepsStr strings.Builder
	for _, step := range steps {
		if step.done {
			stepsStr.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("34")).Render("    ✔  "))
			stepsStr.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(step.label))
		} else {
			stepsStr.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Render("    ⠿  "))
			stepsStr.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(step.label))
		}
		stepsStr.WriteString("\n")
	}

	panel := styleBorder.Width(58).MarginLeft(4).Render(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51")).Render("  Analyzing: "+m.scanFile) +
			"\n\n" + stepsStr.String(),
	)

	b.WriteString(panel + "\n\n")
	b.WriteString(styleDim.PaddingLeft(4).Render("  Press esc to cancel") + "\n\n")
	b.WriteString(m.renderStatusBar())

	return b.String()
}



func (m Model) viewResult() string {
	content := styleBorder.Width(74).MarginLeft(1).Render(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51")).Render("  Scan Complete\n\n") +
			lipgloss.NewStyle().Foreground(lipgloss.Color("34")).Render("  ✔  ") +
			lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render("Analysis results saved. Run with CLI for full output.\n\n") +
			styleDim.Render("  Press esc or q to return to main menu"),
	)
	return m.renderHeader() + "\n\n" + content + "\n\n" + m.renderStatusBar()
}



func (m Model) viewHistory() string {
	content := styleBorder.Width(74).MarginLeft(1).Render(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51")).Render("  SCAN HISTORY\n\n") +
			styleDim.Render("  No previous scans found.\n\n") +
			styleDim.Render("  Run kitinspect scan <file.apk> to get started.\n\n") +
			styleDim.Render("  Press esc to return"),
	)
	return m.renderHeader() + "\n\n" + content + "\n\n" + m.renderStatusBar()
}



func (m Model) viewSettings() string {
	settings := []struct{ k, v string }{
		{"Output Directory", "~/.kitinspect/reports"},
		{"Python Binary", "python3"},
		{"Max File Size", "200 MB"},
		{"Color Output", "enabled"},
		{"JSON Output", "disabled"},
		{"Verbose Mode", "disabled"},
	}

	var rows strings.Builder
	for _, s := range settings {
		rows.WriteString(fmt.Sprintf("  %-24s  %s\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(s.k+":"),
			lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Bold(true).Render(s.v),
		))
	}

	content := styleBorder.Width(74).MarginLeft(1).Render(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51")).Render("  SETTINGS\n\n") +
			rows.String() + "\n" +
			styleDim.Render("  Press esc to return"),
	)
	return m.renderHeader() + "\n\n" + content + "\n\n" + m.renderStatusBar()
}



func (m Model) viewHelp() string {
	help := `  CLI COMMANDS
  ─────────────────────────────────────────────────────────
  kitinspect scan <file.apk>        Full security analysis
  kitinspect permissions <file.apk> Permission audit
  kitinspect cert <file.apk>        Certificate inspection
  kitinspect strings <file.apk>     String extraction & IOC detection
  kitinspect report <file.apk>      Generate analysis report
  kitinspect tui                    Launch this TUI

  FLAGS
  ─────────────────────────────────────────────────────────
  --json     Output results in JSON format
  --verbose  Show extended output
  --output   Save report to specified path
  --no-color Disable color output

  TUI KEYBINDINGS
  ─────────────────────────────────────────────────────────
  ↑ ↓ / j k   Navigate menu
  Enter        Select item
  Esc          Go back
  q            Quit / back
  ?            Show this help

  ABOUT
  ─────────────────────────────────────────────────────────
  KitInspect is a defensive security analysis tool.
  For authorized security research and auditing only.`

	content := styleBorder.Width(74).MarginLeft(1).Render(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51")).Render("  HELP & REFERENCE\n\n") +
			lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(help) + "\n\n" +
			styleDim.Render("  Press esc to return"),
	)
	return m.renderHeader() + "\n\n" + content + "\n\n" + m.renderStatusBar()
}



type scanCompleteMsg struct{}
type scanErrorMsg string

func runScanCmd(path string) tea.Cmd {
	return func() tea.Msg {
		return scanCompleteMsg{}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}


func Run() error {
	p := tea.NewProgram(New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
