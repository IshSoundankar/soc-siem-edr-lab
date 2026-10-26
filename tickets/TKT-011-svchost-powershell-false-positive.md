# TKT-011: svchost masquerading and non-interactive PowerShell

| Field | Value |
| --- | --- |
| Status | Dismissed |
| Severity | High and low (as raised) |
| Rules | Sigma: Suspicious Process Masquerading As SvcHost.EXE; Non Interactive PowerShell Process Spawned |
| Host | WS01 |

**Alert:** LimaCharlie on WS01 at 17:28: "Suspicious Process Masquerading As SvcHost.EXE" (three times) and "Non Interactive PowerShell Process Spawned".

**Checked:**

- `svchost.exe` was in `\Windows\System32`, signed, and started by `services.exe` as SYSTEM.
- The PowerShell was my own admin window (PID 5784). The Security log (event 4688) shows it running the audit-policy commands at 12:15.
- Both were processes already running, listed when the sensor reconnected (`EXISTING_PROCESS`), not new launches.

**Verdict:** false positive. The svchost rule only trusts `C:\Windows\System32\svchost.exe`, but LimaCharlie reports the same file as `\Device\HarddiskVolume2\Windows\System32\svchost.exe`, so the exception never matches. ([rule source](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml))

**Recommended, approval requested:** tune both rules to accept the device-path form.

## Evidence

The four detections at the top of the list, 17:28:29 to 17:28:31.

![EDR detections](../screenshots/08-edr-detections-recon-and-svchost.png)

Key fields from the svchost detection:

```json
"FILE_IS_SIGNED": 1,
"FILE_PATH": "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe",
"PARENT": {
  "FILE_IS_SIGNED": 1,
  "FILE_PATH": "\\Device\\HarddiskVolume2\\Windows\\System32\\services.exe"
},
"USER_NAME": "NT AUTHORITY\\SYSTEM",
"event_type": "EXISTING_PROCESS"
```
