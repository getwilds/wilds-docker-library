# Vulnerability Report for getwilds/deseq2:latest

Report generated on 2025-10-01 09:46:09 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 122 |
| 🟡 Medium | 4057 |
| 🟢 Low | 267 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.17`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 116 |
| 🟡 Medium | 4029 |
| 🟢 Low | 230 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/deseq2:latest         │    4C   122H   4057M   267L   
    digest   │  b4d329722412                           │                               
  Base image │  bioconductor/bioconductor_docker:3.17  │    4C   116H   4029M   230L   

What's next:
    View vulnerabilities → docker scout cves getwilds/deseq2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/deseq2:latest --org <organization>
```
</details>
