# GateKit Contract (LOCK-READY)

## Invariants
- Gate CI is **policy-only**: runs gate scripts + gate-only tests.
- No runtime/integration tests. No DB/network. No full pytest.
- Canonical template: `ci/gate-template/sentinel-gate.yml`
- Drift enforcement: `tools/gates/gate_template_drift_gate.py` (FAIL-CLOSED)

## Allowed substitutions
- `name:` may vary (normalized to `__GATE_NAME__`)
- `__GATE_FILE__` placeholder (normalized)

## Update policy
- Consumers pin GateKit via git submodule commit.
- Updates occur only via explicit "bump gatekit pin" PR.
