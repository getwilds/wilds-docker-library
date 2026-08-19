# Vulnerability Report for getwilds/scater:latest

Report generated on 2026-08-19 23:48:22 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 201 |
| 🟡 Medium | 2813 |
| 🟢 Low | 263 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `bioconductor/bioconductor_docker:3.23`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 10 |
| 🟠 High | 201 |
| 🟡 Medium | 2813 |
| 🟢 Low | 261 |

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target     │  getwilds/scater:latest         │   10C   201H   2813M   263L     2?  
   digest   │  4b4366df0aab                           │                                     
 Base image │  bioconductor/bioconductor_docker:3.23  │   10C   201H   2813M   261L     2?  

Policy status  FAILED  (3/7 policies met, 2 missing data)
Health score  D  (50%)

 Status │                   Policy                   │           Results           
────────┼────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                │                             
 ?      │ No data                                    │    No data                  
 ?      │ No data                                    │    No data                  
 ✓      │ No high-profile vulnerabilities            │    0C     0H     0M     0L  
 ✓      │ No outdated base images                    │                             
 ✓      │ No unapproved base images                  │    0 deviations             
 !      │ Required supply chain attestations missing │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/scater:latest
    View vulnerabilities → docker scout cves getwilds/scater:latest
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/scater:latest
```
</details>
