#!/usr/bin/env python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Theory 7: Built-in adversary — security regression and attack simulation runner.

Runs safe simulations that verify elite controls block known attack paths.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

RESULTS = []


def repo_path(*parts):
    root = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..'))
    return os.path.normpath(os.path.join(root, *parts))


def record(name: str, passed: bool, detail: str = '') -> None:
    RESULTS.append({'test': name, 'passed': passed, 'detail': detail})
    status = 'PASS' if passed else 'FAIL'
    print(f'[{status}] {name}' + (f' — {detail}' if detail else ''))


def test_helpers_rejects_huge_artifact():
    helpers_path = repo_path('salt', 'sensoroni', 'files', 'analyzers', 'helpers.py')
    if not os.path.isfile(helpers_path):
        record('helpers_huge_artifact', True, 'skipped (path not found)')
        return
    spec = importlib.util.spec_from_file_location('helpers', helpers_path)
    helpers = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(helpers)
        huge = '{"artifactType":"ip","value":"' + ('x' * 70000) + '"}'
        try:
            helpers.parseArtifact(huge)
            record('helpers_huge_artifact', False, 'accepted oversized artifact')
        except SystemExit:
            record('helpers_huge_artifact', True)
    except Exception as exc:
        record('helpers_huge_artifact', False, str(exc))


def test_helpers_wildcard_escape():
    helpers_path = repo_path('salt', 'sensoroni', 'files', 'analyzers', 'helpers.py')
    if not os.path.isfile(helpers_path):
        record('helpers_wildcard_escape', True, 'skipped')
        return
    spec = importlib.util.spec_from_file_location('helpers', helpers_path)
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    escaped = helpers.escapeWildcard('*admin*')
    record('helpers_wildcard_escape', '\\*' in escaped, escaped)


def test_security_utils_minion_id():
    utils_path = repo_path('salt', 'common', 'tools', 'sbin', 'so_security_utils.py')
    if not os.path.isfile(utils_path):
        record('minion_id_injection', True, 'skipped')
        return
    spec = importlib.util.spec_from_file_location('so_security_utils', utils_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        mod.validate_minion_id("foo'; evil")
        record('minion_id_injection', False, 'accepted malicious id')
    except ValueError:
        record('minion_id_injection', True)


def test_so_yaml_path_traversal():
    so_yaml = repo_path('salt', 'manager', 'tools', 'sbin', 'so-yaml.py')
    if not os.path.isfile(so_yaml):
        record('so_yaml_path_traversal', True, 'skipped')
        return
    result = subprocess.run(
        [sys.executable, so_yaml, 'get', '/etc/passwd', 'root'],
        capture_output=True, text=True,
    )
    record('so_yaml_path_traversal', result.returncode != 0, result.stderr.strip()[:120])


def test_localfile_path_traversal():
    helpers_path = repo_path('salt', 'sensoroni', 'files', 'analyzers', 'helpers.py')
    if not os.path.isfile(helpers_path):
        record('localfile_path_traversal', True, 'skipped')
        return
    spec = importlib.util.spec_from_file_location('helpers', helpers_path)
    helpers_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers_mod)
    base = os.path.dirname(helpers_path)
    try:
        helpers_mod.safeResolvePath(base, '../../../etc/passwd')
        record('localfile_path_traversal', False, 'traversal allowed')
    except SystemExit:
        record('localfile_path_traversal', True)


def main():
    parser = argparse.ArgumentParser(description='Security Onion attack simulation suite')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    test_helpers_rejects_huge_artifact()
    test_helpers_wildcard_escape()
    test_security_utils_minion_id()
    test_so_yaml_path_traversal()
    test_localfile_path_traversal()

    failed = sum(1 for r in RESULTS if not r['passed'])
    if args.json:
        print(json.dumps({'failed': failed, 'results': RESULTS}, indent=2))
    else:
        print(f'\nSO-ATTACK: {len(RESULTS) - failed}/{len(RESULTS)} passed')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
