# Binwalk Reversing Plugin

This plugin integrates a modern Rust-based version of **[Binwalk](https://github.com/ReFirmLabs/binwalk)** into your reversing workflow. It is designed to identify and extract files or data embedded within other binaries, with a focus on firmware analysis.

## Features

### Actions

* **Scan**: Quickly find embedded data using **Fast** or **Deep** methods.
* **Extract**: Unpack identified files to a directory of your choice.

### Interface

* **Sidebar**: A dedicated view that lists all identified signatures for easy review.
* **Direct Navigation**: Select any result to jump immediately to that specific offset in the disassembler.
* **Folder Selection**: Choose exactly where to save your extracted files.

## Visuals

**Sidebar Example (Shared UI for IDA Pro and Binary Ninja):**

![IDA Pro Sidebar](/images/ida_sidebar.png)

## Backend

The core analysis library is written in Rust and exposed to Python via bindings through [pybinwalk](https://github.com/kevinmuoz/pybinwalk).
The Rust core is cross-platform, currently tested primarily on Ubuntu.

### Current Status and Limitations

This plugin uses the latest version of the Binwalk Rust crate. Because it relies on the current crate release, it does not yet support every feature found in the CLI master branch.

* **Matryoshka (Recursive Extraction)**: Currently not supported in the Rust crate.
* **Updates**: The plugin will be updated to include missing features as soon as new releases of the Rust crate are published.

## Supported Signatures

The plugin detects 60+ signatures, including:

| Category        | Examples                          |
|----------------|-----------------------------------|
| Cryptography   | AES S-Box, MD5/SHA, OpenSSL       |
| Executables    | PE, ELF, Mach-O, Linux Kernel     |
| Compression    | ZSTD, LZMA, SquashFS              |
| Filesystems    | JFFS2, EXT, MBR                   |
| Credentials    | PEM Keys, Certificates, DPAPI     |

Full list:
[Supported Signatures](https://github.com/ReFirmLabs/binwalk/wiki/Supported-Signatures)

## Installation

You can install this plugin directly through the official Plugin Manager in:

* **Binary Ninja**
* **IDA Pro**
