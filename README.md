<div align="center">

```
  ██╗  ██╗██╗████████╗██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗
  ██║ ██╔╝██║╚══██╔══╝██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝
  █████╔╝ ██║   ██║   ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║
  ██╔═██╗ ██║   ██║   ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║
  ██║  ██╗██║   ██║   ██║██║ ╚████║███████║██║      ███████╗╚██████╗   ██║
  ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝      ╚══════╝ ╚═════╝   ╚═╝
```

**Professional Security Analysis Platform**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Defensive Only](https://img.shields.io/badge/Purpose-Defensive%20Analysis%20Only-blue?style=flat)](#)

*Fast · Accurate · Terminal-native*

</div>

---

## Overview

**KitInspect** adalah professional-grade security analysis tool yang berjalan sepenuhnya di terminal sebagai CLI. Tidak ada upload ke cloud, tidak ada dependensi jaringan.

**Core Engine:** Go (fast, zero-dependency binary)

### File yang Didukung

| File Type | Yang Dideteksi |
|---|---|
| **APK** | Permission, certificate, string extraction, IOC, anti-analysis |
| **EXE / DLL** | Process injection, anti-debug, keylogger, registry persistence |
| **ELF** | Shell execution, privilege escalation, network socket, ptrace |
| **PDF** | JavaScript embedded, auto-action, embedded files, JS obfuscation |
| **DOCX / XLS** | Macro auto-execute, shell via macro, network download |
| **ZIP / RAR** | Executable tersembunyi, script files di dalam archive |
| **Semua file** | Hash (MD5/SHA1/SHA256), entropy, IOC, URL, IP, secrets |

---

## Installation

### Requirements
- Go 1.21+

### Build dari Source

```bash
git clone https://github.com/fawwazhakeeeem19/Kitinspect.git
cd Kitinspect
go mod tidy
go build -o Kitinspect ./cmd/
./Kitinspect version
```

### Install ke PATH (opsional)

```bash
sudo cp Kitinspect /usr/local/bin/
```

---

## Usage

### Scan File (Universal)

```bash
./Kitinspect scan file.apk
./Kitinspect scan file.exe
./Kitinspect scan file.pdf
./Kitinspect scan file.docx
./Kitinspect scan file.zip
./Kitinspect scan file.elf
```

Contoh output:

```
  ┌─ FILE METADATA ──────────────────────────────────────────────────
  │  File:                  suspicious.exe
  │  File Type:             PE Executable (Windows EXE/DLL)
  │  File Size:             2.34 MB (2,457,600 bytes)
  │  Magic Bytes:           4D 5A 90 00
  │  MD5:                   a1b2c3d4e5f6...
  │  SHA256:                0123456789abcdef...
  │  Entropy:               7.4821 / 8.0
  │  Packed/Encrypted:      YES — High entropy detected
  └──────────────────────────────────────────────────────────────────

  ┌─ SECURITY FINDINGS ──────────────────────────────────────────────
  │  [CRITICAL] FILE-001  Process Injection Detected
  │             VirtualAlloc, WriteProcessMemory, CreateRemoteThread
  │      Fix: Investigate in isolated sandbox environment.
  │
  │  [HIGH    ] FILE-002  Anti-Debug Detected
  │             IsDebuggerPresent, CheckRemoteDebuggerPresent
  │
  │  [HIGH    ] FILE-003  High Entropy — File Likely Packed/Encrypted
  │             Entropy: 7.48/8.0
  └──────────────────────────────────────────────────────────────────

  ┌─ SECURITY SCORE ─────────────────────────────────────────────────
  │
  │  ████████████████████████████░░░░░░░░░░   72/100  [ HIGH RISK ]
  │
  └──────────────────────────────────────────────────────────────────
```

### Hash File

```bash
./Kitinspect hash file.bin
```

### Ekstrak Strings & IOC

```bash
./Kitinspect strings file.exe
./Kitinspect strings file.exe --verbose
```

### Generate Laporan JSON

```bash
./Kitinspect report file.apk
./Kitinspect report file.exe --output ./laporan.json
```

### Flags

| Flag | Keterangan |
|---|---|
| `--json` | Output dalam format JSON |
| `--verbose` | Tampilkan semua hasil (URLs, strings) |
| `--output <path>` | Simpan laporan ke file |
| `--no-color` | Nonaktifkan warna |

---

## Risk Scoring

Skor **0–100** (semakin tinggi = semakin berisiko):

| Skor | Risk Level | Arti |
|---|---|---|
| 0–24 | 🟢 Low | Indikator minimal |
| 25–49 | 🟡 Medium | Ada pola mencurigakan |
| 50–74 | 🟠 High | Banyak indikator risiko |
| 75–100 | 🔴 Critical | Sangat mencurigakan |

---

## Struktur Project

```
kitinspect/
├── cmd/
│   └── main.go                      # CLI entry point
├── internal/
│   ├── config/
│   │   └── config.go                # Konfigurasi
│   ├── engine/file/
│   │   └── analyzer.go              # Core analysis engine
│   └── output/
│       └── renderer.go              # Terminal output
├── go.mod
└── README.md
```

---

## Legal & Ethics

KitInspect dibuat **khusus** untuk:

- ✅ Security research dan vulnerability disclosure
- ✅ Malware analysis dan threat intelligence
- ✅ Mobile application security auditing
- ✅ Penetration testing (dengan izin tertulis)
- ✅ Edukasi keamanan siber


## License

MIT License

---

<div align="center">
<sub>Built for the security community · Defensive analysis only</sub>
</div>
