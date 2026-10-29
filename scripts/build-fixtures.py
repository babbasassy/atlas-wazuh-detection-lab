"""Generate synthetic Windows event-shaped inputs. Does not execute their contents."""
from copy import deepcopy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def event(provider, channel, event_id, data):
    return {'win': {'system': {'providerName': provider, 'channel': channel,
            'eventID': str(event_id), 'severityValue': 'AUDIT_FAILURE' if event_id == 4625 else 'INFORMATION',
            'computer': 'atlas-client.example.invalid'}, 'eventdata': data}}

logon = event('Microsoft-Windows-Security-Auditing', 'Security', 4625,
              {'logonType': '3', 'targetUserName': 'lab-user', 'ipAddress': '192.0.2.10',
               'status': '0xc000006d', 'subStatus': '0xc000006a'})
process = event('Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon/Operational', 1,
                {'image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                 'commandLine': 'powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEEAVABMAEEAUwAnAA==',
                 'parentImage': r'C:\Windows\System32\cmd.exe', 'user': r'ATLAS\lab-user'})
startup = event('Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon/Operational', 11,
                {'image': r'C:\Windows\explorer.exe', 'targetFilename':
                 r'C:\Users\Lab\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\atlas-demo.lnk'})
cases = []
def add(name, source, expected, change=None):
    data = deepcopy(source)
    if change:
        section, key, value = change
        if value is None: data['win'][section].pop(key, None)
        else: data['win'][section][key] = value
    cases.append({'case': name, 'data_kind': 'synthetic_fixture_not_endpoint_telemetry',
                  'expected_custom_rule': expected, 'event': data})

add('failed-network-logon', logon, '100100')
add('successful-logon', logon, None, ('system', 'eventID', '4624'))
cases[-1]['event']['win']['system']['severityValue'] = 'AUDIT_SUCCESS'
add('interactive-logon', logon, None, ('eventdata', 'logonType', '2'))
add('missing-logon-type', logon, None, ('eventdata', 'logonType', None))
add('wrong-provider', logon, None, ('system', 'providerName', 'Fictional-Provider'))
add('encoded-powershell', process, '100110')
add('mixed-case-encoded-argument', process, '100110', ('eventdata', 'commandLine', 'powershell.exe -EnC VwByAGkAdABlAA=='))
add('ordinary-powershell', process, None, ('eventdata', 'commandLine', "powershell.exe -Command Write-Output ATLAS"))
add('similar-process-name', process, None, ('eventdata', 'image', r'C:\Tools\notpowershell.exe'))
add('missing-command-line', process, None, ('eventdata', 'commandLine', None))
add('startup-shortcut', startup, '100120')
add('uppercase-shortcut', startup, '100120', ('eventdata', 'targetFilename', startup['win']['eventdata']['targetFilename'].upper()))
add('shortcut-outside-startup', startup, None, ('eventdata', 'targetFilename', r'C:\Users\Lab\Desktop\atlas-demo.lnk'))
add('text-in-startup', startup, None, ('eventdata', 'targetFilename', startup['win']['eventdata']['targetFilename'].replace('.lnk', '.txt')))
add('wrong-sysmon-event', startup, None, ('system', 'eventID', '1'))
(ROOT/'fixtures/cases.json').write_text(json.dumps(cases, indent=2)+'\n', encoding='utf-8')
print(f'Wrote {len(cases)} synthetic fixtures; no commands executed.')
