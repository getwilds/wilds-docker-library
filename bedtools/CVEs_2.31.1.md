# Vulnerability Report for getwilds/bedtools:2.31.1

Report generated on 2025-10-01 09:37:49 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1428 |
| 🟢 Low | 40 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 6 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/bedtools:2.31.1  │    0C     5H   1428M    40L   
    digest             │  7ccc610a71d8                      │                               
  Base image           │  ubuntu:24.04                      │    0C     0H    13M     6L    
  Refreshed base image │  ubuntu:24.04                      │    0C     0H     5M     6L    
                       │                                    │                  -8           
  Updated base image   │  ubuntu:25.10                      │    0C     0H     0M     0L    
                       │                                    │                 -13     -6    

What's next:
    View vulnerabilities → docker scout cves getwilds/bedtools:2.31.1
    View base image update recommendations → docker scout recommendations getwilds/bedtools:2.31.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bedtools:2.31.1 --org <organization>
```
</details>
