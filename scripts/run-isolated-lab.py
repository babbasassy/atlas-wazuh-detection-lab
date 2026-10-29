"""Reproduce rule tests without a user-managed VM; requires Python and Docker.

Uses only the pinned, already-downloaded image. No installation, host mount,
published port or network. Removes only the container created by this run.
"""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'wazuh/wazuh-manager:4.14.9@sha256:3561b33f8d1edf3d3b05e1819fa9a47fd28d6536787793d1840bfdf1172359ff'
parser = argparse.ArgumentParser()
parser.add_argument('--docker', default='docker')
args = parser.parse_args()
run_id = datetime.datetime.now(datetime.timezone.utc).strftime('repro-%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:6]
name = 'atlas-wazuh-' + run_id
evidence = ROOT / 'evidence' / (run_id + '-lifecycle')
evidence.mkdir(parents=True, exist_ok=False)
container_id = None
adapter = None

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(filename, obj):
    (evidence/filename).write_text(json.dumps(obj, indent=2)+'\n', encoding='utf-8')

def docker(*parts, check=True, timeout=60):
    p = subprocess.run([args.docker, *parts], capture_output=True, text=True,
        encoding='utf-8', errors='replace', timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'Docker {parts[0]} failed: {p.stderr.strip()}')
    return p

def inspect():
    return json.loads(docker('inspect', container_id).stdout)[0]

def owned():
    info = inspect()
    if info['Config']['Labels'].get('atlas.run') != run_id:
        raise RuntimeError('Run ownership mismatch; refusing mutation')
    return info

def snapshot():
    info = owned()
    config = info['HostConfig']
    return {'at_utc': now(), 'image': info['Config']['Image'], 'state': info['State'],
        'network': config['NetworkMode'], 'ports': config['PortBindings'],
        'mounts': info['Mounts'], 'memory_bytes': config['Memory'],
        'nano_cpus': config['NanoCpus'], 'memory_swap_bytes': config['MemorySwap'],
        'pids_limit': config['PidsLimit'], 'security_options': config['SecurityOpt'],
        'restart_policy': config['RestartPolicy']}

result = {'started_at_utc': now(), 'run_id': run_id, 'image': IMAGE,
          'test_result': 'not_run', 'native_windows_collection': False,
          'source_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((ROOT/'scripts').glob('*')) if p.is_file()}}
try:
    capacity = json.loads(docker('info', '--format', '{{json .MemTotal}}').stdout)
    result['docker_memory_bytes'] = capacity
    host_available = None
    if os.name == 'nt':
        class MemoryStatus(ctypes.Structure):
            _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong)] + [
                (key, ctypes.c_ulonglong) for key in ('total_phys','avail_phys','total_page',
                    'avail_page','total_virtual','avail_virtual','avail_extended')]
        mem = MemoryStatus()
        mem.length = ctypes.sizeof(mem)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
            raise RuntimeError('Could not read host memory')
        host_available = mem.avail_phys
        result['host_available_bytes'] = host_available
        if host_available < 1.25 * 1024**3:
            raise RuntimeError('Less than 1.25 GiB host memory available; defer this run')
    if capacity < 2 * 1024**3:
        raise RuntimeError('Docker reports less than 2 GiB; defer this run')
    image = json.loads(docker('image', 'inspect', IMAGE).stdout)[0]
    if image['Architecture'] != 'amd64' or image['Os'] != 'linux':
        raise RuntimeError('Unexpected image platform')
    save('preflight.json', {'at_utc':now(), 'docker_memory_bytes':capacity,
        'host_available_bytes':host_available, 'image_id':image['Id'], 'image':IMAGE})
    container_id = docker('create', '--pull', 'never', '--name', name,
        '--label', 'atlas.owner=competence-lab', '--label', 'atlas.run='+run_id,
        '--network', 'none', '--memory', '1g', '--memory-swap', '1g', '--cpus', '1',
        '--pids-limit', '256', '--security-opt', 'no-new-privileges', '--restart', 'no',
        '--entrypoint', '/bin/bash', IMAGE, '-c', 'exec sleep 900').stdout.strip()
    runtime = snapshot()
    if not (runtime['network'] == 'none' and not runtime['ports'] and not runtime['mounts']
            and runtime['memory_bytes'] == 1024**3 and runtime['memory_swap_bytes'] == 1024**3
            and runtime['nano_cpus'] == 10**9 and runtime['pids_limit'] == 256
            and runtime['restart_policy']['Name'] == 'no'
            and any('no-new-privileges' in item for item in runtime['security_options'])):
        raise RuntimeError('Container isolation does not match the lab contract')
    docker('start', container_id)
    save('runtime.json', snapshot())
    for source, target in [('scripts/initialize-container.sh','/tmp/atlas-init.sh'),
        ('scripts/logtest-json-adapter.py','/tmp/atlas-adapter.py')]:
        docker('cp', str(ROOT/source), container_id+':'+target)
    p = docker('exec', container_id, '/bin/bash', '/tmp/atlas-init.sh', timeout=120)
    (evidence/'initialization.txt').write_text(p.stdout+p.stderr, encoding='utf-8')
    docker('cp', str(ROOT/'rules/atlas_windows_rules.xml'),
        container_id+':/var/ossec/etc/rules/atlas_windows_rules.xml')
    p = docker('exec', container_id, '/var/ossec/framework/python/bin/python3', '/tmp/atlas-adapter.py')
    adapter = json.loads(p.stdout)
    save('adapter.json', adapter)
    docker('exec', container_id, '/var/ossec/bin/wazuh-analysisd', '-t')
    docker('exec', container_id, '/var/ossec/bin/wazuh-db')
    docker('exec', container_id, '/var/ossec/bin/wazuh-analysisd')
    ready = False
    for _ in range(20):
        if docker('exec', container_id, 'test', '-S', '/var/ossec/queue/sockets/logtest', check=False).returncode == 0:
            ready = True
            break
        time.sleep(0.5)
    if not ready:
        raise RuntimeError('Wazuh logtest socket did not become ready')
    p = subprocess.run([sys.executable, str(ROOT/'scripts/run-rule-tests.py'),
        '--docker', args.docker, '--container', container_id, '--run', run_id],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=360)
    (evidence/'test-runner.txt').write_text(p.stdout+p.stderr, encoding='utf-8')
    print(p.stdout, end='')
    result['test_result'] = 'passed' if p.returncode == 0 else 'failed'
    result['test_summary'] = '../'+run_id+'/summary.json'
    if p.returncode:
        raise RuntimeError('One or more rule tests failed; see captured outputs')
except Exception as exc:
    result['error'] = str(exc)
    print(str(exc), file=sys.stderr)
finally:
    if container_id:
        try:
            save('runtime-after-test.json', snapshot())
            base = '/var/ossec/ruleset/rules/0575-win-base_rules.xml'
            if adapter is not None:
                docker('exec', container_id, 'cp', base+'.atlas-original', base)
                p = docker('exec', container_id, 'sha256sum', base)
                result['restored_base_sha256'] = p.stdout.split()[0]
                if result['restored_base_sha256'] != adapter['source_sha256']:
                    raise RuntimeError('Restored base rule does not match original hash')
                result['base_restore_verified'] = True
        except Exception as exc:
            result['restore_or_snapshot_error'] = str(exc)
        try:
            owned()
            docker('stop', '--timeout', '10', container_id, timeout=30)
            docker('rm', container_id)
            listing = docker('ps', '-a', '--filter', 'id='+container_id, '--format', '{{.ID}}').stdout.strip()
            if listing:
                raise RuntimeError('Container remains after cleanup')
            result['cleanup'] = 'own_container_removed'
        except Exception as exc:
            result['cleanup_error'] = str(exc)
            print('CLEANUP REQUIRES ATTENTION: '+str(exc), file=sys.stderr)
    else:
        result['cleanup'] = 'no_container_created'
    result['finished_at_utc'] = now()
    save('result.json', result)
    print('Evidence: '+str(evidence))
raise SystemExit(0 if result['test_result'] == 'passed'
    and result.get('cleanup') == 'own_container_removed'
    and result.get('base_restore_verified') is True
    and not result.get('error') and not result.get('restore_or_snapshot_error') else 1)
