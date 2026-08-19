# Vulnerability Report for getwilds/scater:1.40.2

Report generated on 2026-08-19 23:37:17 PST

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
Target     │  getwilds/scater:1.40.2         │   10C   201H   2813M   263L     2?  
   digest   │  d424cc461d04                           │                                     
 Base image │  bioconductor/bioconductor_docker:3.23  │   10C   201H   2813M   261L     2?  

Policy status  FAILED  (2/7 policies met, 3 missing data)
Health score  E  (28%)

 Status │                   Policy                   │     Results     
────────┼────────────────────────────────────────────┼─────────────────
 !      │ Image runs as the root user                │                 
 ?      │ No data                                    │    No data      
 ?      │ No data                                    │    No data      
 ?      │ No data                                    │    No data      
 ✓      │ No outdated base images                    │                 
 ✓      │ No unapproved base images                  │    0 deviations 
 !      │ Required supply chain attestations missing │    2 deviations 

What's next:
    View policy violations → docker scout policy getwilds/scater:1.40.2
    View vulnerabilities → docker scout cves getwilds/scater:1.40.2
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/scater:1.40.2
```
</details>
