# Vulnerability Report for getwilds/umitools:latest

Report generated on 2026-10-23 19:03:06 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 12 |
| 🟡 Medium | 15 |
| 🟢 Low | 65 |
| ⚪ Unknown | 11 |

## 🐳 Base Image

**Image:** `python:3.11-slim-bookworm`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 11 |
| 🟡 Medium | 15 |
| 🟢 Low | 51 |

## 🔄 Recommendations

**Updated base image:** `python:3.12-slim-bookworm`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/umitools:latest-amd64  │    0C    12H    15M    65L    11?  
   digest           │  5c096a993cf3                            │                                    
 Base image         │  python:3.11-slim-bookworm               │    0C    11H    15M    51L         
 Updated base image │  python:3.12-slim-bookworm               │    0C     9H    14M    51L         
                    │                                          │           -2     -1                

Policy status  FAILED  (3/7 policies met)
Health score  D  (50%)

 Status │                     Policy                     │           Results           
────────┼────────────────────────────────────────────────┼─────────────────────────────
 !      │ Image runs as the root user                    │                             
 !      │ Copyleft licensed packages found               │    411 packages             
 !      │ Fixable critical or high vulnerabilities found │    0C     2H     0M     0L  
 ✓      │ No high-profile vulnerabilities                │    0C     0H     0M     0L  
 ✓      │ No outdated base images                        │                             
 ✓      │ No unapproved base images                      │    0 deviations             
 !      │ Required supply chain attestations missing     │    2 deviations             

What's next:
    View policy violations → docker scout policy getwilds/umitools:latest-amd64
    View vulnerabilities → docker scout cves getwilds/umitools:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/umitools:latest-amd64
    Compare with the latest in the registry → docker scout compare --to-latest getwilds/umitools:latest-amd64
```
</details>
