# Vulnerability Report for getwilds/gatk:4.6.1.0

Report generated on 2026-10-03 15:19:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 53 |
| 🟡 Medium | 88 |
| 🟢 Low | 23 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 8 |
| 🟢 Low | 7 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/gatk:4.6.1.0  │    2C    53H    88M    23L  
   digest           │  605597b3ff92                   │                             
 Base image         │  ubuntu:24.04                   │    0C     1H     8M     7L  
 Updated base image │  ubuntu:26.04                   │    0C     0H     0M     0L  
                    │                                 │           -1     -8     -7  

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    689 packages             
 !      │ Fixable critical or high vulnerabilities found │    2C    53H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/gatk:4.6.1.0
    View vulnerabilities → docker scout cves getwilds/gatk:4.6.1.0
    View base image update recommendations → docker scout recommendations getwilds/gatk:4.6.1.0
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/gatk:4.6.1.0
```
</details>
