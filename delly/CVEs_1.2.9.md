# Vulnerability Report for getwilds/delly:1.2.9

Report generated on 2025-10-01 09:38:29 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 16 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 13 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/delly:1.2.9  │    0C     0H     4M    16L   
    digest           │  ed545c79d49b                  │                              
  Base image         │  ubuntu:22.04                  │    0C     0H     4M    13L   
  Updated base image │  ubuntu:25.10                  │    0C     0H     0M     0L   
                     │                                │                  -4    -13   

What's next:
    View vulnerabilities → docker scout cves getwilds/delly:1.2.9
    View base image update recommendations → docker scout recommendations getwilds/delly:1.2.9
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/delly:1.2.9 --org <organization>
```
</details>
