"""Exercise the real Wazuh engine with explicitly synthetic fixtures.

Requires the prepared isolated atlas-wazuh-rulecheck container and JSON adapter.
No input command or encoded payload is executed.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--docker', required=True)
parser.add_argument('--run', default='adapted-json-run-1')
parser.add_argument('--container', default='atlas-wazuh-rulecheck')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
assert re.fullmatch(r'[a-z0-9-]+', args.run)
out = root / 'evidence' / args.run
out.mkdir(parents=True, exist_ok=False)
fixtures = root / 'fixtures/cases.json'
cases = json.loads(fixtures.read_text(encoding='utf-8'))
(out/'input-cases.json').write_bytes(fixtures.read_bytes())
(out/'tested-rules.xml').write_bytes((root/'rules/atlas_windows_rules.xml').read_bytes())
results = []
for case in cases:
    p = subprocess.run([args.docker, 'exec', '-i', args.container,
        '/var/ossec/bin/wazuh-logtest', '-l', 'EventChannel'],
        input=json.dumps(case['event'])+'\n', text=True, capture_output=True, timeout=20,
        encoding='utf-8', errors='replace')
    raw = p.stdout + '\nSTDERR:\n' + p.stderr
    (out / (case['case']+'.txt')).write_text(raw, encoding='utf-8')
    ids = re.findall(r"^\s*id: '([0-9]+)'", raw, re.M)
    actual = ids[-1] if ids else None
    decoded = 'Phase 2: Completed decoding.' in raw and "name: 'json'" in raw
    filtered = 'Phase 3: Completed filtering (rules).' in raw
    expected = case['expected_custom_rule']
    matched = actual == expected if expected else actual not in {'100100','100110','100120'}
    passed = p.returncode == 0 and decoded and filtered and actual is not None and matched
    results.append({'case': case['case'], 'expected_custom_rule': expected,
        'observed_final_rule': actual, 'json_decoded': decoded, 'filtered': filtered,
        'process_exit_code': p.returncode, 'passed': passed})
    print(f"{case['case']}: {'PASS' if passed else 'FAIL'} observed={actual} expected={expected}")
summary = {'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'engine': 'Wazuh 4.14.9 wazuh-logtest', 'input': 'synthetic JSON, never endpoint telemetry',
    'adapter': 'rule 60000 input gate changed to json inside disposable container',
    'native_windows_decoder_verified': False, 'live_collection_verified': False,
    'fixtures_sha256': hashlib.sha256(fixtures.read_bytes()).hexdigest(),
    'custom_rules_sha256': hashlib.sha256((root/'rules/atlas_windows_rules.xml').read_bytes()).hexdigest(),
    'passed': sum(r['passed'] for r in results), 'failed': sum(not r['passed'] for r in results),
    'results': results}
(out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
raise SystemExit(0 if summary['failed'] == 0 else 1)
