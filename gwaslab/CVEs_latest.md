# Vulnerability Report for getwilds/gwaslab:latest

Report generated on 2026-07-30 18:02:10 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 7 |
| 🟢 Low | 29 |
| ⚪ Unknown | 7 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 7 |
| 🟢 Low | 29 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/gwaslab:latest-amd64  │    1C     2H     7M    29L     7?  
   digest           │  766000715c0d                           │                                    
 Base image         │  python:3.12-slim                       │    1C     2H     7M    29L     7?  
 Updated base image │  python:3.13-slim                       │    1C     2H     3M    28L     7?  
                    │                                         │                  -4     -1         

Policy status  FAILED  (4/7 policies met)
Health score  B  (72%)

 Status │                   Policy                    │           Results           
────────┼─────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                 │                             
 !      │ Copyleft licensed packages found            │    368 packages             
 ✓      │ No fixable critical or high vulnerabilities │    0C     0H     0M     0L  
 ✓      │ No high-profile vulnerabilities             │    0C     0H     0M     0L  
 ✓      │ No outdated base images                     │                             
 ✓      │ No unapproved base images                   │    0 deviations             
 !      │ Required supply chain attestations missing  │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/gwaslab:latest-amd64
    View vulnerabilities → docker scout cves getwilds/gwaslab:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/gwaslab:latest-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/gwaslab:latest-amd64
```
</details>
