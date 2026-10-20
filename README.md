# 🔍 C++ ELF Binary Analyzer

<p align="center">
  A lightweight C++17 tool for inspecting Linux ELF binaries through static analysis.
  <br>
  Analyze binary metadata, program segments, sections, symbols, and selected security indicators — without executing the target file.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B17-00599C?logo=cplusplus" alt="C++17">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Analysis-Static-2E8B57" alt="Static Analysis">
  <img src="https://img.shields.io/badge/Build-Makefile-blue" alt="Makefile">
</p>

---

## 📌 About the Project

The **C++ ELF Binary Analyzer** is a command-line utility that examines Executable and Linkable Format (ELF) files used by Linux systems.

It helps explore how executables are organized, how program segments are mapped into memory, and how symbol tables and security-related metadata can be inspected.

## ✨ Key Features

| Feature | Description |
|---|---|
| 🧩 ELF Identification | Identifies ELF32/ELF64 formats and byte order |
| 🖥️ Binary Metadata | Displays architecture, file type, and entry point |
| 📦 Program Headers | Examines program segments and their permissions |
| 🗂️ Section Analysis | Displays section names, sizes, addresses, types, and flags |
| 🔎 Symbol Inspection | Reads `SYMTAB` and `DYNSYM` entries when available |
| 🔐 Security Indicators | Checks selected properties, including GNU stack permissions and writable-executable segments |
| 🛡️ Input Validation | Performs bounds checks on file offsets and table sizes |

## 🛠️ Built With

- **C++17** — implementation
- **g++** — compilation
- **Make** — build automation
- **Linux / WSL Ubuntu** — execution environment

## 🚀 Getting Started

### Prerequisites

Install the required tools on Ubuntu:

```bash
sudo apt update
sudo apt install g++ make
```

### Installation

Clone your repository:

```bash
git clone https://github.com/YOUR-USERNAME/elf-binary-analyzer.git
cd elf-binary-analyzer
```

### Build

```bash
make
```

### Run

Analyze a Linux executable:

```bash
./elf-analyzer /bin/ls
```

Analyze another ELF binary:

```bash
./elf-analyzer ./your-program
```

## 🔐 Security Indicators

The analyzer reports selected properties that can help with basic binary inspection.

| Indicator | Significance |
|---|---|
| `GNU_STACK` | Indicates stack permission settings |
| `GNU_RELRO` | Identifies a RELRO segment |
| Writable + Executable | Highlights segments with both permissions |
| `ET_DYN` | May represent a shared library or a PIE executable |
| `PT_INTERP` | Identifies program interpreter information |

> **Note:** These indicators are informational. They do not prove that a binary is safe, vulnerable, or malicious.

## 📂 Project Structure

```text
elf-binary-analyzer/
├── elf_analyzer.cpp
├── Makefile
├── README.md
└── .gitignore
```

## ⚠️ Limitations

- Stripped binaries may contain limited symbol information.
- Displayed symbols are limited to 200.
- Extended program-header numbering is not supported.
- Dynamic-tag decoding, relocation analysis, and DWARF debug information are not implemented yet.
- This project is intended for learning and basic inspection, not as a replacement for professional forensic tools.


<p align="center">
  <strong>Built with C++17 · Systems Programming · Binary Analysis</strong>
</p>
