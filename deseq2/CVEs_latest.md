# Vulnerability Report for getwilds/deseq2:latest

Report generated on 2025-11-01 09:51:37 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 136 |
| 🟡 Medium | 4066 |
| 🟢 Low | 275 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.17`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 130 |
| 🟡 Medium | 4037 |
| 🟢 Low | 238 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/deseq2:latest         │    4C   136H   4066M   275L   
    digest   │  7dcde63f26f2                           │                               
  Base image │  bioconductor/bioconductor_docker:3.17  │    4C   130H   4037M   238L   

What's next:
    View vulnerabilities → docker scout cves getwilds/deseq2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/deseq2:latest --org <organization>
```
</details>
