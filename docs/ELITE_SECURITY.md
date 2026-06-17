# Elite security documentation for Security Onion hardening layers.

Security Onion ships seven interconnected elite security theories:

1. **Control plane** — `so_security_utils.py`, `so-yaml.py` allowlists, `pillarWatch` cmd allowlist, VM schema validation, audit log at `/opt/so/log/security/audit.log`
2. **Enrichment zero trust** — `helpers.py`, `egress_policy.yaml`, analyzer timeouts, `verify_cert` pillar option
3. **Detection loop** — `so-response`, `playbook_runner.py`, tiered actions with `--approve`
4. **AI-native SOC** — `investigation_context.schema.json`, `ai_guardrails.json`
5. **Resilience** — `circuit_breaker.py`, fcntl locks, healthcheck state allowlist
6. **Supply chain** — `so-verify`, read-only analyzers when `elite_security` enabled on sensors
7. **Built-in adversary** — `tests/security/so-attack.py`, `test_elite_security.py`

Enable elite mode in SOC → Grid → Sensoroni → `elite_security` and `verify_cert`.

Run verification:

```bash
so-verify --strict
python3 tests/security/so-attack.py
```
