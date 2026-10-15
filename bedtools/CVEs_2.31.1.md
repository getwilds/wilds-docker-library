# Vulnerability Report for getwilds/bedtools:2.31.1

Report generated on 2026-09-25 17:04:55 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 14 |
| 🟢 Low | 2 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 9 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/bedtools:2.31.1-amd64  │    0C     0H    14M     2L  
   digest           │  274c2b76db02                            │                             
 Base image         │  ubuntu:24.04                            │    0C     0H     9M     2L  
 Updated base image │  ubuntu:26.04                            │    0C     0H     0M     0L  
                    │                                          │                  -9     -2  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    444 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/bedtools:2.31.1-amd64
    View vulnerabilities → docker scout cves getwilds/bedtools:2.31.1-amd64
    View base image update recommendations → docker scout recommendations getwilds/bedtools:2.31.1-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/bedtools:2.31.1-amd64
```
</details>
