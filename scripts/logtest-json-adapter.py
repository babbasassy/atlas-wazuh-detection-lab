"""TEST ONLY: run inside the disposable ATLAS container, never a live manager.

Windows EventChannel is not supported natively by wazuh-logtest. This adapts
only rule 60000's input gate for synthetic JSON; it cannot validate collection.
Source: https://github.com/wazuh/wazuh/discussions/25405
"""
import hashlib
import json
from pathlib import Path

path = Path('/var/ossec/ruleset/rules/0575-win-base_rules.xml')
original = path.read_bytes()
needle = b'<category>ossec</category>\n    <decoded_as>windows_eventchannel</decoded_as>'
assert original.count(needle) == 1, 'Unexpected source; refuse ambiguous modification'
adapted = original.replace(needle, b'<decoded_as>json</decoded_as>')
path.with_suffix('.xml.atlas-original').write_bytes(original)
path.write_bytes(adapted)
print(json.dumps({'scope': 'ephemeral_container_only', 'native_eventchannel_tested': False,
    'source_sha256': hashlib.sha256(original).hexdigest(),
    'adapted_sha256': hashlib.sha256(adapted).hexdigest(),
    'change': 'rule 60000: remove ossec category, use json decoder; preserve level 0'}, indent=2))
