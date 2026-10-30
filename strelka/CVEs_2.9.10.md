# Vulnerability Report for getwilds/strelka:2.9.10

Report generated on 2026-10-30 19:43:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 38 |
| 🟢 Low | 10 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 19 |
| 🟢 Low | 7 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/strelka:2.9.10  │    0C     0H    38M    10L  
   digest           │  a10b45393fc2                     │                             
 Base image         │  ubuntu:22.04                     │    0C     0H    19M     7L  
 Updated base image │  ubuntu:26.04                     │    0C     0H     0M     0L  
                    │                                   │                 -19     -7  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    259 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/strelka:2.9.10
    View vulnerabilities → docker scout cves getwilds/strelka:2.9.10
    View base image update recommendations → docker scout recommendations getwilds/strelka:2.9.10
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/strelka:2.9.10
```
</details>
