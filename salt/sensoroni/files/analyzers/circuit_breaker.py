"""
Theory 5: Per-provider circuit breaker for Sensoroni analyzers.

Trips after consecutive failures; auto-resets after cooldown.
"""

import json
import os
import time

STATE_DIR = '/opt/so/state/analyzer_circuits'
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_COOLDOWN_SECONDS = 300


def _state_path(provider: str) -> str:
    safe = ''.join(c if c.isalnum() or c in '-_' else '_' for c in provider)
    return os.path.join(STATE_DIR, f'{safe}.json')


def _load(provider: str) -> dict:
    path = _state_path(provider)
    if os.path.isfile(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'failures': 0, 'open_until': 0}


def _save(provider: str, state: dict) -> None:
    os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
    with open(_state_path(provider), 'w', encoding='utf-8') as f:
        json.dump(state, f)


def is_open(provider: str) -> bool:
    state = _load(provider)
    if state.get('open_until', 0) > time.time():
        return True
    return False


def record_success(provider: str) -> None:
    _save(provider, {'failures': 0, 'open_until': 0})


def record_failure(provider: str, threshold: int = DEFAULT_FAILURE_THRESHOLD,
                   cooldown: int = DEFAULT_COOLDOWN_SECONDS) -> bool:
    state = _load(provider)
    failures = int(state.get('failures', 0)) + 1
    open_until = state.get('open_until', 0)
    if failures >= threshold:
        open_until = time.time() + cooldown
        failures = 0
    _save(provider, {'failures': failures, 'open_until': open_until})
    return open_until > time.time()
