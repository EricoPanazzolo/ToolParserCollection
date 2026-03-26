# 🛠️ Tool Parser Collection

A collection of small utilities to transform raw security tool outputs into clean, readable formats.

The goal of this repository is to make recon and pentest results easier to analyze, share, and report.


## 📦 Available Parsers

### 🔎 Nuclei → HTML

Converts the default `nuclei -o` output into a clean, interactive HTML report.

#### ✨ Features
- 🔍 Search across all findings
- 🎯 Filter by severity and protocol
- 📊 Quick severity overview (stats)
- 📄 Expand raw output per finding
- ⚡ Works with standard nuclei text output

## 🚀 Usage

```bash
nuclei2html.py ~/path/to/nuclei/output.txt output.html
```

---

### 🔎 Comming Soon
