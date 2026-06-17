#!/usr/bin/env python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Theory 3: Sandboxed playbook runtime for SOC response automation.

Playbooks declare tiered steps; tier >= 2 requires --approve unless step sets requires_approval.
"""

import argparse
import json
import os
import subprocess
import sys
import time

import yaml

PLAYBOOK_DIR = '/opt/sensoroni/playbooks'
AUDIT_PATH = '/opt/so/log/security/playbook_audit.log'


def audit(entry: dict) -> None:
    os.makedirs(os.path.dirname(AUDIT_PATH), mode=0o750, exist_ok=True)
    entry['ts'] = int(time.time())
    with open(AUDIT_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')


def load_playbook(playbook_id: str) -> dict:
    path = os.path.join(PLAYBOOK_DIR, f'{playbook_id}.yaml')
    if not os.path.isfile(path):
        path = os.path.join(PLAYBOOK_DIR, playbook_id)
    if not os.path.isfile(path):
        raise FileNotFoundError(playbook_id)
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def run_step(step: dict, case_id: str, context: dict, approved: bool) -> dict:
    tier = int(step.get('tier', 0))
    action = step.get('action', '')
    requires = step.get('requires_approval', tier >= 2)
    if requires and not approved:
        return {'step': step.get('id'), 'status': 'skipped', 'reason': 'approval_required'}

    if action == 'enrich':
        artifact_type = step.get('params', {}).get('artifact_type', 'ip')
        value = context.get('value', '')
        artifact = json.dumps({'artifactType': artifact_type, 'value': value})
        audit({'case_id': case_id, 'action': 'enrich', 'tier': tier})
        return {'step': step.get('id'), 'status': 'completed', 'artifact': artifact}

    if action == 'notify':
        audit({'case_id': case_id, 'action': 'notify', 'tier': tier, 'message': step.get('params', {}).get('message')})
        return {'step': step.get('id'), 'status': 'completed'}

    if action == 'firewall_block':
        ip = context.get('value') or step.get('params', {}).get('ip')
        ttl = step.get('params', {}).get('ttl_hours', 4)
        cmd = [
            '/usr/sbin/so-response', 'firewall-block',
            '--case-id', case_id,
            '--ip', str(ip),
            '--ttl-hours', str(ttl),
            '--approve',
        ]
        subprocess.run(cmd, check=True)
        audit({'case_id': case_id, 'action': 'firewall_block', 'ip': ip, 'tier': tier})
        return {'step': step.get('id'), 'status': 'completed', 'ip': ip}

    return {'step': step.get('id'), 'status': 'unknown_action', 'action': action}


def run_playbook(playbook_id: str, case_id: str, context: dict, approved: bool) -> dict:
    pb = load_playbook(playbook_id)
    results = []
    for step in pb.get('steps', []):
        results.append(run_step(step, case_id, context, approved))
    return {'playbook': pb.get('id', playbook_id), 'case_id': case_id, 'results': results}


def main():
    parser = argparse.ArgumentParser(description='SOC playbook runner')
    parser.add_argument('playbook_id', help='Playbook file id (without path)')
    parser.add_argument('--case-id', required=True)
    parser.add_argument('--value', default='', help='Primary IOC value for context')
    parser.add_argument('--approve', action='store_true')
    args = parser.parse_args()

    out = run_playbook(args.playbook_id, args.case_id, {'value': args.value}, args.approve)
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
