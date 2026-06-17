#!/usr/bin/env python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Shared security utilities for Security Onion elite hardening (Theories 1, 5, 6).

Provides path allowlists, identifier validation, cross-process file locks,
VM config schema validation, audit logging, and command allowlisting.
"""

import json
import os
import re
import ipaddress
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import fcntl
except ImportError:
    fcntl = None

# Theory 1: control-plane paths that may be modified by automation tools.
ALLOWED_YAML_ROOTS = (
    '/opt/so/saltstack/local/',
    '/opt/so/conf/',
)

ALLOWED_FILE_READ_ROOTS = (
    '/opt/so/saltstack/local/',
    '/opt/so/conf/',
)

MINION_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,253}$')
VM_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$')
VALID_VM_ROLES = frozenset({'sensor', 'searchnode', 'idh', 'receiver', 'heavynode', 'fleet'})
PCI_RE = re.compile(r'^\d{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.\d$')

AUDIT_LOG = '/opt/so/log/security/audit.log'

# Theory 1 + 5: pillarWatch / automation command allowlist (prefix match).
ALLOWED_CMD_PREFIXES = (
    '/usr/sbin/so-yaml.py ',
    'salt-call state.apply kafka',
    'salt-call state.apply elasticfleet',
    'salt -C ',
    'salt-call state.apply kafka.nodes',
)

ALLOWED_STATE_APPLY_TARGETS = frozenset({
    'kafka.nodes',
    'kafka',
    'kafka.disabled',
    'kafka.reset',
    'elasticfleet',
    'zeek',
    'healthcheck',
})

DEFAULT_LOCK_PATH = '/opt/so/state/so-security.lock'


def audit_event(action: str, detail: Dict[str, Any], actor: str = 'system') -> None:
    """Append a tamper-evident audit record (Theory 1)."""
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), mode=0o750, exist_ok=True)
        record = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'actor': actor,
            'action': action,
            'detail': detail,
        }
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, separators=(',', ':')) + '\n')
    except OSError:
        pass


def realpath_under(path: str, allowed_roots: Tuple[str, ...]) -> str:
    resolved = os.path.realpath(path)
    for root in allowed_roots:
        root_real = os.path.realpath(root)
        if resolved == root_real or resolved.startswith(root_real + os.sep):
            return resolved
    raise PermissionError(f'Path not allowed: {path}')


def validate_yaml_path(path: str) -> str:
    return realpath_under(path, ALLOWED_YAML_ROOTS)


def validate_file_read_path(path: str) -> str:
    return realpath_under(path, ALLOWED_FILE_READ_ROOTS)


def validate_minion_id(minion_id: str) -> str:
    if not minion_id or not MINION_ID_RE.match(minion_id):
        raise ValueError(f'Invalid minion ID: {minion_id!r}')
    return minion_id


def validate_ip_or_cidr(value: str) -> str:
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f'Invalid IP or CIDR: {value!r}') from exc
    return value


def validate_vm_config(vm: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Theory 1: schema validation for hypervisor *VMs JSON entries."""
    if not isinstance(vm, dict):
        return False, 'VM config must be an object'
    hostname = vm.get('hostname')
    role = vm.get('role')
    if not hostname or not VM_HOSTNAME_RE.match(str(hostname)):
        return False, f'Invalid hostname: {hostname!r}'
    if role not in VALID_VM_ROLES:
        return False, f'Invalid role: {role!r}'
    if 'network_mode' in vm and vm['network_mode'] not in ('static4', 'dhcp4'):
        return False, f'Invalid network_mode: {vm.get("network_mode")!r}'
    for field in ('ip4', 'gw4', 'dns4'):
        if field in vm and vm[field]:
            try:
                validate_ip_or_cidr(str(vm[field]).split('/')[0])
            except ValueError:
                return False, f'Invalid {field}: {vm[field]!r}'
    for field in ('cpu', 'memory', 'nsm_size'):
        if field in vm and vm[field] is not None:
            try:
                val = int(vm[field])
                if val <= 0:
                    return False, f'{field} must be positive'
            except (TypeError, ValueError):
                return False, f'Invalid {field}: {vm[field]!r}'
    return True, None


def is_allowed_cmd(cmd: str) -> bool:
    """Theory 1 + 5: restrict pillarWatch cmd.run to known-safe prefixes."""
    if not isinstance(cmd, str) or not cmd.strip():
        return False
    normalized = cmd.strip()
    return any(normalized.startswith(prefix) for prefix in ALLOWED_CMD_PREFIXES)


def is_allowed_state_apply(states: str) -> bool:
    if not states:
        return False
    for part in states.replace(',', ' ').split():
        base = part.split('.')[0:2]
        target = '.'.join(base) if len(base) > 1 else part
        if target not in ALLOWED_STATE_APPLY_TARGETS and part not in ALLOWED_STATE_APPLY_TARGETS:
            return False
    return True


@contextmanager
def file_lock(lock_path: str = DEFAULT_LOCK_PATH, fail_closed: bool = True):
    """Theory 5: cross-process exclusive lock using fcntl (Unix)."""
    if fcntl is None:
        yield
        return
    os.makedirs(os.path.dirname(lock_path), mode=0o750, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o640)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if fail_closed:
                raise RuntimeError(f'Could not acquire lock: {lock_path}')
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def load_allowlists(config_path: str = '/opt/so/conf/security/allowlists.json') -> Dict[str, Any]:
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}
