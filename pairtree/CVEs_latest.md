# Vulnerability Report for getwilds/pairtree:latest

Report generated on 2026-09-11 22:16:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 5 |
| 🟠 High | 132 |
| 🟡 Medium | 2017 |
| 🟢 Low | 214 |
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

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/pairtree:latest-amd64  │    5C   132H   2017M   214L  
   digest             │  9d83a234bc79                            │                              
 Base image           │  ubuntu:24.04                            │    0C     2H    83M    34L   
 Refreshed base image │  ubuntu:24.04                            │    0C     0H    13M     2L   
                      │                                          │           -2    -70    -32   

Policy status  FAILED  (2/7 policies met)
Health score  E  (28%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    538 packages             
 !      │ Fixable critical or high vulnerabilities found │    0C    12H     0M     0L  
 !      │ High-profile vulnerabilities found             │    0C     1H     0M     0L  
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
