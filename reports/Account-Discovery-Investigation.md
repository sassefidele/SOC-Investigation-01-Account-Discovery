# SOC Investigation Report #001

## Windows Account Discovery — Sysmon and Wazuh

| Investigation detail | Value |
|---|---|
| Investigation date | November 11–12, 2026 |
| Endpoint | `SOC-WIN11-01` |
| SIEM | Wazuh |
| Log source | Microsoft Sysmon |
| Detection rule | `92031` |
| MITRE ATT&CK | T1087 — Account Discovery |
| Alert severity | Level 3 |
| Investigation status | Initial triage completed |
| Disposition | Likely benign monitoring activity |

## 1. Executive Summary

A Wazuh detection identified Windows account-discovery activity on endpoint `SOC-WIN11-01`.

The detection was generated from Sysmon Event ID 1, which records process creation.

Investigation of the process execution chain revealed that the Wazuh agent launched `net.exe`, which subsequently launched `net1.exe`.

The commands were executed under the `NT AUTHORITY\SYSTEM` account.

Available evidence suggests the activity was associated with legitimate endpoint monitoring. No malicious activity was established by the investigated events.

## 2. Detection Details

| Attribute | Value |
|---|---|
| Detection description | Discovery activity executed |
| Wazuh rule ID | `92031` |
| Sysmon Event ID | `1` |
| MITRE tactic | Discovery |
| MITRE technique | T1087 — Account Discovery |
| Command | `net user` |
| Executable | `net.exe` / `net1.exe` |
| Execution account | `NT AUTHORITY\SYSTEM` |

## 3. Process Tree

```text
wazuh-agent.exe
    |
    +-- net.exe
           |
           +-- net1.exe
```

The parent-child relationship was identified through Sysmon process-creation telemetry collected by Wazuh.

## 4. Investigation Procedure

The investigation included:

1. Verifying Sysmon installation and process-creation logging.
2. Confirming that the Wazuh Windows agent was running.
3. Configuring Wazuh to collect the Sysmon Operational event channel.
4. Confirming Sysmon events appeared in the Wazuh manager's alert logs.
5. Extracting detection details using Linux command-line tools.
6. Examining process names, command lines, execution accounts, and parent processes.
7. Searching for rule 92031 in the Wazuh Threat Hunting dashboard.
8. Reviewing the alert's MITRE ATT&CK classification.

## 5. Findings

The investigated process executions were associated with the Wazuh agent.

The observed account-enumeration commands are consistent with legitimate system-monitoring activity, although the exact Wazuh module responsible was not conclusively identified.

The detection demonstrates that legitimate administrative commands can trigger security alerts because the same techniques may also be used by attackers.

## 6. Assessment

**Classification:** Likely benign activity.

**Confidence:** Moderate.

**Rationale:** The process ancestry identifies the Wazuh agent as the initiating process. The activity is consistent with endpoint monitoring, but the precise internal component responsible remains unconfirmed.

## 7. Recommendations

- Retain Sysmon process-creation logging.
- Continue monitoring account-discovery activity.
- Correlate future detections with process ancestry and execution context.
- Avoid broadly suppressing rule 92031.
- Consider narrowly scoped detection tuning only after additional validation.

## 8. Conclusion

This investigation demonstrated practical SOC capabilities involving endpoint telemetry collection, SIEM integration, MITRE ATT&CK mapping, process-tree analysis, and alert triage.

The investigated alert was classified as likely benign rather than malicious based on the available evidence.
