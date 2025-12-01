# Vulnerability Report for getwilds/sourmash:latest

Report generated on 2025-12-01 09:31:41 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 19 |
| 🟢 Low | 4 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:20.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/sourmash:latest  │    0C     2H    19M     4L   
    digest           │  784069414473                      │                              
  Base image         │  ubuntu:20.04                      │    0C     0H     5M     0L   
  Updated base image │  ubuntu:26.04                      │    0C     0H     0M     0L   
                     │                                    │                  -5          

What's next:
    View vulnerabilities → docker scout cves getwilds/sourmash:latest
    View base image update recommendations → docker scout recommendations getwilds/sourmash:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/sourmash:latest --org <organization>
```
</details>
