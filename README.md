# C++ ELF Binary Analyzer

A lightweight static analyzer for Linux ELF files. It reads binary data directly and does **not** execute the file being inspected.

## Features

- ELF32 and ELF64 identification
- Little-endian and big-endian integer decoding
- ELF file type, machine architecture, entry point, and file size
- Program headers and load-segment permissions
- Section names, types, sizes, addresses, and flags
- Symbol tables (`SYMTAB` and `DYNSYM`) when present
- Basic security indicators: PIE-compatible `ET_DYN`, GNU stack permissions, GNU RELRO, interpreter segment, and writable+executable load segments
- Bounds checks for file offsets and table sizes; rejects files larger than 512 MiB

## Build

Requires a C++17 compiler such as `g++` on Linux.

```bash
make
```

Or:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic elf_analyzer.cpp -o elf-analyzer
```

## Run

```bash
./elf-analyzer /bin/ls
./elf-analyzer ./your-program
```

You can create a test binary:

```bash
printf 'int main(){return 0;}\n' > sample.c
gcc -g sample.c -o sample
./elf-analyzer ./sample
```

## Output guide

- **Program headers** describe segments the loader maps into memory.
- **Sections** describe logical parts of the file, such as `.text` (code), `.rodata` (read-only data), and `.data` (initialized writable data).
- **Symbols** can identify functions and objects if symbol tables are available. Stripped files may not contain a regular symbol table.
- **Security indicators** are heuristics, not a security certification or malware verdict. `ET_DYN` is used by shared libraries and commonly by PIE executables; this tool does not conclusively distinguish them. Missing metadata does not automatically mean maliciousness.

## Limitations

- This is a learning project, not a replacement for `readelf`, `objdump`, or a hardened forensic parser.
- It does not decode dynamic tags, relocations, GNU build IDs, versioned symbols, or DWARF debug data yet.
- It caps displayed symbols at 200 to keep output manageable.
- Malformed or unusual ELF variants may be rejected; extended program-header numbering is not implemented.

## Suggested next improvements

1. Parse dynamic tags and list imported shared libraries (`DT_NEEDED`).
2. Parse relocation entries and identify unresolved or suspicious imports.
3. Add JSON output and automated malformed-input tests.
4. Add a comparison mode for two ELF files.

## Safety

Analyze only files you are authorized to inspect. The analyzer treats the target as data and never launches it.
