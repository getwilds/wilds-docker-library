# Vulnerability Report for getwilds/deseq2:latest

Report generated on 2025-10-06 16:24:13 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 122 |
| 🟡 Medium | 4064 |
| 🟢 Low | 267 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.17`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 116 |
| 🟡 Medium | 4036 |
| 🟢 Low | 230 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/deseq2:latest         │    4C   122H   4064M   267L   
    digest   │  4ad9c4dee5eb                           │                               
  Base image │  bioconductor/bioconductor_docker:3.17  │    4C   116H   4036M   230L   

What's next:
    View vulnerabilities → docker scout cves getwilds/deseq2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/deseq2:latest --org <organization>
```
</details>
