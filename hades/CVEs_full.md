# Vulnerability Report for getwilds/hades:full

Report generated on 2026-08-18 17:30:09 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 169 |
| 🟡 Medium | 1988 |
| 🟢 Low | 131 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `oisupport/staging-amd64:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 4 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/hades:full    │    4C   169H   1988M   131L     2?  
   digest   │  a760d4d7baa0                   │                                     
 Base image │  oisupport/staging-amd64:24.04  │    0C     0H     5M     4L          

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    1506 packages            
 !      │ Fixable critical or high vulnerabilities found │    4C   127H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/hades:full
    View vulnerabilities → docker scout cves getwilds/hades:full
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/hades:full
```
</details>
