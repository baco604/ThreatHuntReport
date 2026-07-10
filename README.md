# Northpeak Descent — Threat Hunt Writeup

**Platform:** Microsoft Sentinel / Microsoft Defender for Endpoint (MDE)
**Scope:** Cross-platform intrusion — Windows estate + Linux host
**Environment:** Northpeak Logistics (simulated) — `npt-ws01`, `npt-srv01`, `npt-linux01`
**Window:** Evening of 16 June 2026 – morning of 17 June 2026 (UTC)
**Hunt type:** Community hunt, built by Dogukan Oruc, Cyber Range SOC

## Scenario

Northpeak Logistics' estate was compromised on the evening of 16 June. The operator established two parallel footholds — one on the Windows infrastructure via external RDP, one on a Linux host for reconnaissance and tooling — then pivoted internally, staged tooling, planted persistence, stood up C2, and exfiltrated data. A loud brute-force logon storm was present in the logs as a decoy; the real entry authenticated cleanly and never tripped an alert.

This writeup documents the reconstruction of the full intrusion chain using KQL queries against `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, and `DeviceRegistryEvents`.

## Methodology

- Scoped every query to the Northpeak hosts (`npt-ws01`, `npt-srv01`, `npt-linux01`) in a shared Sentinel workspace to avoid pulling telemetry from other tenants.
- Treated the failed-logon volume as noise and worked forward only from successful, external authentications.
- Built a single cross-platform timeline from both Windows and Linux telemetry rather than assuming which system was compromised first.
- Distinguished automated/system chatter (Defender's own background processes, Azure guest agent noise) from hands-on-keyboard operator activity by tracing parent-process lineage (e.g. `explorer.exe → powershell.exe` vs. `senseir.exe → powershell.exe`).
- Treated absence of evidence as a finding in its own right — most notably, the complete lack of AV/EDR tampering.

## Key Findings

### 1. Initial Access
The real access vector to `npt-srv01` was a clean external RDP (`RemoteInteractive`) logon authenticated via Negotiate/NTLM from a single external IP (`148.64.103.173`) — not a pivot from inside the network, and not the brute-force noise that dominated the logs.

### 2. Linux Recon & Tooling
On `npt-linux01`, the operator:
- Ran standard privilege enumeration (`sudo -l`), fumbling it once (`sudo -1`) before the correct command six minutes later.
- Tested Windows-host reachability using bash's built-in `/dev/tcp` pseudo-device — no scanner dropped on the box — confirming RDP (port 3389) was open on both Windows targets.
- Committed to installing **NetExec** (via `pipx`), pulling in `impacket`, `Certipy`, `oscrypto`, and `NfsClient` as dependencies.

### 3. Pivot, Execution & Persistence
- Lateral movement from Linux (`10.2.0.30`) to `npt-ws01` via SMB/NTLM using NetExec and the `sancadmin` account.
- The operator's own hands-on-keyboard PowerShell sessions were distinguishable from Defender's automated diagnostic noise by parent process: `explorer.exe → powershell.exe` (human) vs. `senseir.exe / gc_worker.exe → powershell.exe` (automated MDE/Azure Guest Configuration chatter).
- Persistence was planted via an `HKCU\...\CurrentVersion\Run` key (`NorthpeakSyncTray`) launching a disguised PowerShell script (`NorthpeakSyncTray.ps1`) on every logon, surviving reboots.
- A narrow Windows Defender exclusion was added for the persistence path/process — not a wholesale disabling of AV, just enough to keep it quiet.

### 4. Command & Control
The beacon used three look-alike subdomains under `sync-northpeak.com` (`status.`, `updates.`, `cdn.`), but the network sensor only ever recorded one of them, and even that connection failed. The other two only appear in process command-line telemetry (base64-encoded `-EncodedCommand` PowerShell), meaning the network view alone would have completely missed two-thirds of the C2 channel. The beacon's fixed ~38-second check-in interval confirmed it was a scheduled, automated loop — not manual operator activity.

### 5. Impact & Judgment
- A file (`customer_data_export_20260616.csv`) was staged in `C:\Temp` on `npt-srv01` and uploaded to `cdn.sync-northpeak.com` within 17 seconds of creation.
- The exfil occurred during a **second, distinct RDP session** — the operator had disconnected and reconnected (fresh `RemoteInteractive` logon + `Unlock` event) roughly two hours after the original session, from the same external IP.
- Most notably: across the entire multi-hour intrusion, there was **no tampering with the security stack** — no disabled real-time protection, no stopped services, no dropped tooling. Everything was living-off-the-land (native binaries, `pip`-installed public tools) run under a single legitimate, already-trusted admin account. That's why nothing tripped for hours: the account itself was the vulnerability, not any exploit or malware.

## Intrusion Chain Summary

```
External RDP (148.64.103.173) → npt-srv01 (clean auth, no brute force)
        │
        ▼
Parallel Linux foothold → npt-linux01 recon (sudo -l, /dev/tcp reachability checks)
        │
        ▼
NetExec install → SMB/NTLM lateral movement → npt-ws01 (as sancadmin)
        │
        ▼
Run key persistence (NorthpeakSyncTray.ps1) + narrow Defender exclusion
        │
        ▼
C2 beacon → sync-northpeak.com (3 subdomains, 1 visible on network, fixed interval)
        │
        ▼
Second RDP session → data staged (customer_data_export_20260616.csv) → exfil via cdn.sync-northpeak.com
```

## Takeaways

- **Volume ≠ signal.** The loudest thing in the logs (the brute-force storm) was irrelevant; the real entry was a single clean authentication.
- **Parent-process lineage matters more than the command itself.** Identical PowerShell invocations from `explorer.exe` vs. a system service told two completely different stories.
- **Network telemetry is not the whole picture.** Two-thirds of the C2 infrastructure was invisible to `DeviceNetworkEvents` and only recoverable from process command-line data.
- **The absence of tampering is itself a high-confidence finding.** An intrusion that never touches the security stack because it never needed to — because it already holds legitimate credentials — is arguably the most dangerous pattern to detect, and the one most worth hunting for explicitly.

---

*Hunt completed against the `law-cyber-range` Sentinel workspace. All IOCs, hostnames, and account names in this writeup are specific to the simulated Northpeak Logistics range environment.*
