# Vulnerability Report for getwilds/pairtree:latest

Report generated on 2026-09-22 16:29:51 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 85 |
| 🟡 Medium | 2293 |
| 🟢 Low | 158 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 83 |
| 🟢 Low | 34 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/pairtree:latest-amd64  │    1C    85H   2293M   158L  
   digest             │  59842546eaa0                            │                              
 Base image           │  ubuntu:24.04                            │    0C     2H    83M    34L   
 Refreshed base image │  ubuntu:24.04                            │    0C     0H     7M     2L   
                      │                                          │           -2    -76    -32   
 Updated base image   │  ubuntu:26.04                            │    0C     0H     0M     0L   
                      │                                          │           -2    -83    -34   

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    538 packages             
 !      │ Fixable critical or high vulnerabilities found │    0C    12H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/pairtree:latest-amd64
    View vulnerabilities → docker scout cves getwilds/pairtree:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/pairtree:latest-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/pairtree:latest-amd64
```
</details>
