# Detection rationale and review notes

These rules are narrow examples tested against synthetic JSON in a real Wazuh engine. The adapter and exact parent hierarchy matter; passing cases do not establish production detection coverage.

| Rule | Trigger tested | Positive controls | Negative controls | First review steps |
|---|---|---|---|---|
| 100100 | Security event 4625, expected audit provider, logon type 3, parent 60122 | One failed network logon | Successful logon, interactive logon, missing logon type, wrong provider | Check account, source, failure reason, recent successful logons and repeated failures. One event is not a brute-force finding. |
| 100110 | Sysmon process event under 61603; path ends in powershell.exe/pwsh.exe; command contains -enc or -encodedcommand plus a value | Full argument and mixed-case shortened argument | Ordinary command, similar process filename, missing command line | Review process lineage, script provenance and approved administration. Decode only as data in an isolated analysis workflow; never execute unknown command text. |
| 100120 | Sysmon file creation under 61613; target is a direct .lnk child of a Windows Startup directory | Normal and uppercase paths | Desktop shortcut, .txt in Startup, wrong event type | Check installer/change context, shortcut target and creating process before escalation. Legitimate applications may use this location. |

## What the assertions mean

Every case must exit successfully, complete JSON decoding and rule filtering, produce a final rule ID, and match its expected outcome. Negative cases may match built-in rules; they pass only when none of the three ATLAS rules is the final rule. Each case uses a separate logtest session. No multi-event frequency/timeframe correlation is tested.

## Known coverage limits

- The PowerShell rule tests two argument spellings, not every accepted abbreviation, quoting form, renamed executable or evasion technique. `pwsh.exe` is permitted in the expression but has no dedicated positive fixture in this set.
- The Startup rule covers shortcut creation at a specific path shape, not registry autoruns, scheduled tasks or all persistence mechanisms.
- Event fields are constructed for rule testing, not faithful full records from a Windows host. The successful-logon negative fixture changes event ID/severity while retaining other seed fields; it is not a reference Windows 4624 record.
- This is a small deterministic suite, not a false-positive rate measurement, adversarial benchmark or production tuning exercise.
- No authentication attempt, process payload, Startup shortcut, account action or endpoint change is performed by the fixtures. Command lines and paths are inert input strings.

## Optional live validation

Only in a separately authorized isolated Windows environment: validate the original native decoder and unmodified vendor rules, collect benign events through an agent, and compare source events, decoded fields and resulting alerts. Keep that evidence separate from these synthetic test results. Never install the JSON test adapter on a live manager.
