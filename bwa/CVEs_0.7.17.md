# Vulnerability Report for getwilds/bwa:0.7.17

Report generated on 2026-09-25 04:33:24 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 11 |
| 🟢 Low | 2 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 8 |
| 🟢 Low | 2 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/bwa:0.7.17  │    0C     0H    11M     2L  
   digest           │  4bc61972ae66                 │                             
 Base image         │  ubuntu:24.04                 │    0C     0H     8M     2L  
 Updated base image │  ubuntu:26.04                 │    0C     0H     0M     0L  
                    │                               │                  -8     -2  

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    441 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/bwa:0.7.17
    View vulnerabilities → docker scout cves getwilds/bwa:0.7.17
    View base image update recommendations → docker scout recommendations getwilds/bwa:0.7.17
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/bwa:0.7.17
```
</details>
