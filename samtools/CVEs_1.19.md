# Vulnerability Report for getwilds/samtools:1.19

Report generated on 2026-09-18 18:24:34 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 2 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 7 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/samtools:1.19-amd64  │    0C     0H    13M     2L  
   digest           │  d17c4a988444                          │                             
 Base image         │  ubuntu:24.04                          │    0C     0H     7M     2L  
 Updated base image │  ubuntu:26.04                          │    0C     0H     0M     0L  
                    │                                        │                  -7     -2  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    442 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/samtools:1.19-amd64
    View vulnerabilities → docker scout cves getwilds/samtools:1.19-amd64
    View base image update recommendations → docker scout recommendations getwilds/samtools:1.19-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/samtools:1.19-amd64
```
</details>
