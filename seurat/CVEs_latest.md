# Vulnerability Report for getwilds/seurat:latest

Report generated on 2026-05-30 02:30:29 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 45 |
| 🟡 Medium | 3083 |
| 🟢 Low | 123 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor:3.21`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 45 |
| 🟡 Medium | 3082 |
| 🟢 Low | 121 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/seurat:latest  │    3C    45H   3083M   123L  
   digest   │  14e9c932be20                    │                              
 Base image │  bioconductor/bioconductor:3.21  │    3C    45H   3082M   121L  

What's next:
    View vulnerabilities → docker scout cves getwilds/seurat:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/seurat:latest --org <organization>
```
</details>
