package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kitinspect/kitinspect/internal/config"
	fileengine "github.com/kitinspect/kitinspect/internal/engine/file"
	"github.com/kitinspect/kitinspect/internal/output"
	"github.com/spf13/cobra"
)

var (
	cfg         = config.Default()
	flagJSON    bool
	flagVerbose bool
	flagOutput  string
	flagNoColor bool
)



var rootCmd = &cobra.Command{
	Use:   "kitinspect",
	Short: "KitInspect — Professional Security Analysis Tool",
	Long: `
KitInspect is a professional-grade security analysis tool.
Supports: APK, EXE, DLL, ELF, PDF, DOCX, XLSX, ZIP, RAR, and more.

For authorized security research and defensive auditing only.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if flagNoColor {
			os.Setenv("NO_COLOR", "1")
		}
		cfg.Verbose = flagVerbose
		cfg.JSONOutput = flagJSON
		cfg.EnsureDirs()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}



var scanCmd = &cobra.Command{
	Use:   "scan <file>",
	Short: "Scan any file — APK, EXE, DLL, ELF, PDF, DOCX, ZIP, and more",
	Long: `Universal file security scanner. Automatically detects file type and runs
appropriate analysis:

  APK   → Permission analysis, certificate, string extraction, IOC detection
  EXE   → PE analysis, process injection, anti-debug, persistence detection
  DLL   → Same as EXE
  ELF   → Linux binary analysis, shell execution, privilege escalation
  PDF   → JavaScript detection, embedded files, auto-action analysis
  DOCX  → Macro detection, command execution, obfuscation
  ZIP   → Archive contents, embedded executables/scripts
  Any   → Hash generation, entropy, string extraction, IOC detection`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if err := validateFile(path); err != nil {
			return err
		}

		if !cfg.JSONOutput {
			output.PrintBanner()
		}

		result, err := runFileScan(path)
		if err != nil {
			return err
		}

		if cfg.JSONOutput {
			output.PrintJSON(result)
			return nil
		}

		output.PrintFileMeta(&result.Meta)
		output.PrintFileStrings(&result.Strings, cfg.Verbose)
		output.PrintFileIOCs(result.IOCs)
		output.PrintFileFindings(result.Findings)
		output.PrintScoreGauge(result.Score.Overall, result.Score.RiskLevel)
		output.PrintFileSummary(result)

		if flagOutput != "" {
			return saveFileReport(result, flagOutput)
		}
		return nil
	},
}



var stringsCmd = &cobra.Command{
	Use:     "strings <file>",
	Aliases: []string{"str"},
	Short:   "Extract strings, URLs, IPs, and secrets from any file",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if err := validateFile(path); err != nil {
			return err
		}
		if !cfg.JSONOutput {
			output.PrintBanner()
		}
		result, err := runFileScan(path)
		if err != nil {
			return err
		}
		if cfg.JSONOutput {
			output.PrintJSON(map[string]interface{}{
				"file":    result.Meta.FileName,
				"strings": result.Strings,
				"iocs":    result.IOCs,
			})
			return nil
		}
		output.PrintFileMeta(&result.Meta)
		output.PrintFileStrings(&result.Strings, cfg.Verbose)
		output.PrintFileIOCs(result.IOCs)
		return nil
	},
}



var hashCmd = &cobra.Command{
	Use:   "hash <file>",
	Short: "Generate MD5, SHA1, SHA256 hashes of a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if err := validateFile(path); err != nil {
			return err
		}
		if !cfg.JSONOutput {
			output.PrintBanner()
		}
		result, err := runFileScan(path)
		if err != nil {
			return err
		}
		if cfg.JSONOutput {
			output.PrintJSON(map[string]interface{}{
				"file":   result.Meta.FileName,
				"md5":    result.Meta.MD5,
				"sha1":   result.Meta.SHA1,
				"sha256": result.Meta.SHA256,
			})
			return nil
		}
		output.PrintFileMeta(&result.Meta)
		return nil
	},
}



var reportCmd = &cobra.Command{
	Use:   "report <file>",
	Short: "Generate a full security report and save to JSON",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if err := validateFile(path); err != nil {
			return err
		}

		output.PrintBanner()

		result, err := runFileScan(path)
		if err != nil {
			return err
		}

		outPath := flagOutput
		if outPath == "" {
			base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			ts := time.Now().Format("20060102-150405")
			outPath = filepath.Join(cfg.OutputDir, fmt.Sprintf("kitinspect_%s_%s.json", base, ts))
		}

		if err := saveFileReport(result, outPath); err != nil {
			return err
		}

		output.PrintFileMeta(&result.Meta)
		output.PrintFileFindings(result.Findings)
		output.PrintScoreGauge(result.Score.Overall, result.Score.RiskLevel)
		output.PrintFileSummary(result)
		output.Success(fmt.Sprintf("Report saved: %s", outPath))
		return nil
	},
}



var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("KitInspect %s\n", config.Version)
		fmt.Printf("Professional Security Analysis Platform\n")
		fmt.Printf("\nSupported file types:\n")
		fmt.Printf("  APK  EXE  DLL  ELF  PDF  DOCX  XLSX  ZIP  RAR  and more\n")
	},
}



func runFileScan(path string) (*fileengine.ScanResult, error) {
	if !cfg.JSONOutput {
		stop := output.Spinner("Analyzing " + filepath.Base(path))
		result, err := fileengine.NewAnalyzer().Scan(path)
		stop()
		if err != nil {
			output.Error(err.Error())
			return nil, err
		}
		return result, nil
	}
	return fileengine.NewAnalyzer().Scan(path)
}

func validateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", path)
		}
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty: %s", path)
	}
	if info.Size() > cfg.MaxFileMB*1024*1024 {
		return fmt.Errorf("file too large (%.0f MB, max %d MB)",
			float64(info.Size())/(1024*1024), cfg.MaxFileMB)
	}
	return nil
}

func saveFileReport(result *fileengine.ScanResult, outPath string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("cannot create report: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}



func init() {
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "Show extended output")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "", "Save report to file")

	rootCmd.AddCommand(scanCmd, stringsCmd, hashCmd, reportCmd, versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
