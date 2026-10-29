# Verification index

The engine tests were executed on the dates below. Publication checks on 29 October 2026 inspect the saved evidence and source bytes; they are not new Wazuh runs.

| Observation | Outcome | Evidence |
|---|---|---|
| 16 October, first manual harness | 0/15 reported passed; output-stream and fixture/rule issues investigated | [Original summary and adjacent raw outputs](adapted-json-run-1/summary.json) |
| 16 October, corrected manual run | 15/15 passed in the real engine with a JSON adapter | [Summary](adapted-json-run-2/summary.json), [adapter hashes](json-adapter.json), [cleanup](cleanup.json) |
| 17 October, automated attempt | Not run: available memory below the guard; no container created | [Lifecycle result](repro-20261017-132017-098c6b-lifecycle/result.json) |
| 27 October, first automated attempt | Initialization failed before tests; own container removed | [Lifecycle result](repro-20261027-185337-883035-lifecycle/result.json) |
| 27 October, corrected automated run | 15/15 passed; original base-rule hash restored; own container removed | [Summary](repro-20261027-185423-da963c/summary.json), [lifecycle result](repro-20261027-185423-da963c-lifecycle/result.json) |

## Trace the successful automated run

1. [Copied inputs](repro-20261027-185423-da963c/input-cases.json) and [tested rules](repro-20261027-185423-da963c/tested-rules.xml) have SHA-256 values recorded in the summary. Each named case has a raw `.txt` logtest output in the same directory.
2. The summary records expected custom rule, observed final rule, JSON decoding, filtering and process exit. Five cases expect one of the three ATLAS rules. Ten controls expect none of them; a built-in rule can still match.
3. The lifecycle result records hashes of the five reproduction scripts. The published scripts and fixtures are byte-for-byte checked against those records. `.gitattributes` disables text conversion so a checkout preserves those hashes.
4. [Runtime inspection](repro-20261027-185423-da963c-lifecycle/runtime.json) records network `none`, empty ports and mounts, 1 GiB memory/swap, one CPU, 256 processes, no new privileges and no restart. [Post-test inspection](repro-20261027-185423-da963c-lifecycle/runtime-after-test.json) records the container state before cleanup.
5. [Adapter metadata](repro-20261027-185423-da963c-lifecycle/adapter.json) records the original and modified base-rule hashes. The lifecycle's restored hash matches the original; the runner then removed only its own labeled container and checked that its ID was absent.
6. [Publication verification](release-verification.json) records source/evidence consistency, raw-output agreement and local document-link checks. Its file hashes cover the selected publication files except that report itself.

The two successful runs cover the same 15 scenario names, not 30 distinct scenarios. The older manual run does not include copied input files; its historical hashes and raw outputs are preserved without claiming they match the current fixtures.

## Interpretation limits

The JSON input gate is a temporary test adapter in a disposable container. These results demonstrate real rule-engine execution on synthetic data, not native Windows EventChannel decoding, installed agents, Sysmon collection, dashboard ingestion, a protected endpoint or a person's independent proficiency. No payload command was executed. See [detection coverage and triage](../docs/DETECTIONS.md).

This repository contains the custom rules, test tools, synthetic fixtures, raw case outputs and selected lifecycle evidence. Image-download logs and repetitive initialization transcripts remain local. No vendor image, binary, original vendor rule file, credentials or private endpoint telemetry is included.
