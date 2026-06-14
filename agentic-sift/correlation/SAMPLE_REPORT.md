# Forensic Investigation Report

**Investigation ID:** inv-samplecase
**Evidence:** `/opt/sans_hackathon/evidence/base-sample-case-cdrive.E01`
**Evidence Type:** disk
**Timestamp:** 2026-06-04T10:30:00Z
**Status:** complete
**Rounds Completed:** 3

## Executive Summary

Investigation analyzed `/opt/sans_hackathon/evidence/base-sample-case-cdrive.E01` over 3 rounds. Found 10 findings (7 confirmed, 3 inferred) and 8 IOCs.

## Hypotheses

### H1: Malware downloaded and persisted via registry Run key and service install
**Status:** SUPPORTED
**Evidence for:**
- File written to Temp
- Registry Run key created
- Service installed
- Prefetch confirms execution

### H2: Attacker harvested credentials and moved laterally to domain controller
**Status:** SUPPORTED
**Evidence for:**
- Mimikatz detected in PowerShell logs
- NTLM auth with harvested creds
- PsExec execution confirmed via Amcache

## Findings

### Finding 1: Browser history: download of svchost_update.exe from http://evil-update.example.com/update.exe
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**IOC:** domain = `evil-update.example.com`
**Evidence:** execution IDs EX-009

### Finding 2: Suspicious executable C:\Windows\Temp\svchost_update.exe written (SHA256: a1b2c3d4)
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**IOC:** file_path = `C:\Windows\Temp\svchost_update.exe`
**Evidence:** execution IDs EX-001

### Finding 3: Registry Run key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate -> svchost_update.exe
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**IOC:** registry_key = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate`
**Evidence:** execution IDs EX-002

### Finding 4: Event Log 7045: Service WindowsUpdateSvc installed (svchost_update.exe)
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**IOC:** file_path = `C:\Windows\Temp\svchost_update.exe`
**Evidence:** execution IDs EX-003

### Finding 5: Prefetch: SVCHOST_UPDATE.EXE execution confirmed at 02:15 UTC
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**Evidence:** execution IDs EX-004

### Finding 6: Outbound C2 connection to 185.143.223.47:443 from svchost_update.exe
**Confidence:** inferred (verified: confirmed)
**Agent:** disk_agent
**IOC:** ip = `185.143.223.47`
**Evidence:** execution IDs EX-005

### Finding 7: PowerShell Event 4104: Invoke-Mimikatz script block detected
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**IOC:** file_path = `Invoke-Mimikatz`
**Evidence:** execution IDs EX-006

### Finding 8: NTLM auth to DC 10.0.0.1 with harvested credentials (Event 4624 Type 3)
**Confidence:** inferred (verified: confirmed)
**Agent:** disk_agent
**IOC:** ip = `10.0.0.1`
**Evidence:** execution IDs EX-007

### Finding 9: Amcache: PsExec.exe executed for lateral movement
**Confidence:** confirmed (verified: confirmed)
**Agent:** disk_agent
**IOC:** file_path = `PsExec.exe`
**Evidence:** execution IDs EX-008

### Finding 10: MFT SI timestamp for svchost_update.exe backdated to 2017-01-01 (possible timestomping)
**Confidence:** inferred (verified: confirmed)
**Agent:** disk_agent
**Evidence:** execution IDs EX-010

## Indicators of Compromise

| Type | Value |
|------|-------|
| domain | `evil-update.example.com` |
| file_path | `C:\Windows\Temp\svchost_update.exe` |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate` |
| file_path | `C:\Windows\Temp\svchost_update.exe` |
| ip | `185.143.223.47` |
| file_path | `Invoke-Mimikatz` |
| ip | `10.0.0.1` |
| file_path | `PsExec.exe` |

## Attack Timeline

| Time (UTC) | Artifact | Description |
|------------|----------|-------------|
| 2018-07-04T02:12:45Z | browser | Browser history: download of svchost_update.exe from http://evil-update.example.com/update.exe |
| 2018-07-04T02:14:33Z | mft | Suspicious executable C:\Windows\Temp\svchost_update.exe written (SHA256: a1b2c3d4) |
| 2018-07-04T02:14:47Z | registry | Registry Run key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate -> svchost_update.exe |
| 2018-07-04T02:15:02Z | evtx | Event Log 7045: Service WindowsUpdateSvc installed (svchost_update.exe) |
| 2018-07-04T02:15:18Z | prefetch | Prefetch: SVCHOST_UPDATE.EXE execution confirmed at 02:15 UTC |
| 2018-07-04T02:16:01Z | evtx | Outbound C2 connection to 185.143.223.47:443 from svchost_update.exe |
| 2018-07-04T08:33:12Z | evtx | PowerShell Event 4104: Invoke-Mimikatz script block detected |
| 2018-07-04T08:35:44Z | evtx | NTLM auth to DC 10.0.0.1 with harvested credentials (Event 4624 Type 3) |
| 2018-07-04T08:36:15Z | amcache | Amcache: PsExec.exe executed for lateral movement |
| UNKNOWN | mft | MFT SI timestamp for svchost_update.exe backdated to 2017-01-01 (possible timestomping) |

### Event Chains

- **CH-001** (inferred): Browser history: download of svchost_update.exe from http://evil-update.example.com/update.exe → Suspicious executable C:\Windows\Temp\svchost_update.exe written (SHA256: a1b2c3d4) → Registry Run key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate -> svchost_update.exe → Event Log 7045: Service WindowsUpdateSvc installed (svchost_update.exe) → Prefetch: SVCHOST_UPDATE.EXE execution confirmed at 02:15 UTC → Outbound C2 connection to 185.143.223.47:443 from svchost_update.exe
- **CH-002** (inferred): PowerShell Event 4104: Invoke-Mimikatz script block detected → NTLM auth to DC 10.0.0.1 with harvested credentials (Event 4624 Type 3) → Amcache: PsExec.exe executed for lateral movement → MFT SI timestamp for svchost_update.exe backdated to 2017-01-01 (possible timestomping)

### Timeline Gaps

- **A-001** [gap]: No events for 6.3 hours (2018-07-04T02:16:01Z — 2018-07-04T08:33:12Z)

### Semantic Activity Groups

- **svchost_update.exe full lifecycle** (F-001, F-002, F-003, F-004, F-005, F-006)
  - Six findings trace svchost_update.exe from download through file write, registry persistence, service install, execution, and C2 callback
- **Credential theft and lateral movement** (F-007, F-008, F-009)
  - Mimikatz credential harvesting followed by NTLM authentication with stolen creds and PsExec lateral movement

## Failed Approaches

- **foremost**: Requires extracted files, not raw image
  Lesson: Use icat to extract first
- **bulk_extractor**: Timeout on full image scan
  Lesson: Target specific partitions

## Strategy Pivots

- From: Network analysis
  To: Registry + Prefetch
  Reason: No PCAP on disk image; pivoted to host-based persistence artifacts

## Accuracy Metadata

- Total findings: 10
- Confirmed (direct evidence): 7
- Inferred (correlated): 3
- Possible (weak signal): 0
- Verified by challenger agent: 10
- Refuted by challenger (removed from report): 0

## Audit Trail

Full execution log: `audit.jsonl`

- Tool executions logged: 47
- Agent messages logged: 23
- Total audit events: 70
