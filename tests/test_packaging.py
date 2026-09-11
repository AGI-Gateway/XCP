"""
test_packaging.py — the published image must contain what the code imports.

This exists because it already went wrong: the gateway Dockerfile copied only
`xcp_gateway.py`, while the gateway had grown imports of `trustfirewall.limits`
and `xcpsec`. The image that Helm deployed therefore ran with abuse controls and
the argument firewall silently absent — the exact open-relay failure those
controls exist to prevent.

Unit tests could not catch that, because they run against the source tree. These
check the packaging itself.

    python tests/test_packaging.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DOCKERFILE = ROOT / "Dockerfile"
ENTRYPOINT = ROOT / "entrypoint.sh"


def _copied_dirs() -> set[str]:
    out = set()
    for line in DOCKERFILE.read_text().splitlines():
        m = re.match(r"COPY\s+(\S+)/\s+/app/", line.strip())
        if m:
            out.add(m.group(1).strip("/"))
    return out


def test_image_contains_every_package_the_runtime_imports():
    """
    Every top-level package the running services import must be copied in.
    Missing one is invisible until production, because the imports are guarded.
    """
    needed = {"core", "trustfirewall", "security", "vault", "trust",
              "federation", "connectors", "receipts", "providers", "discovery"}
    copied = _copied_dirs()
    missing = needed - copied
    assert not missing, f"Dockerfile does not copy: {sorted(missing)}"


def test_gateway_runtime_imports_are_all_packaged():
    """Derive the requirement from the source rather than a hand-kept list."""
    src = (ROOT / "core" / "gateway" / "xcp_gateway.py").read_text()
    referenced = set(re.findall(r"from\s+([a-z_]+)[\. ]", src))
    external = {"fastapi", "httpx", "prometheus_client", "dataclasses",
                "typing", "__future__", "collections", "urllib", "os", "sys",
                "json", "time", "threading", "enum", "pathlib", "hashlib"}
    local = {r for r in referenced if (ROOT / r).is_dir()} - external
    copied = _copied_dirs()
    assert local <= copied, f"gateway imports {sorted(local - copied)}, not in the image"


def test_every_role_has_an_entrypoint_branch():
    sh = ENTRYPOINT.read_text()
    for role in ("gateway", "server", "verifier"):
        assert f"{role})" in sh, f"entrypoint has no branch for {role}"
    assert "exit 2" in sh, "an unknown role must fail, not default to something"


def test_entrypoint_modules_are_importable_by_package_path():
    for mod in ("core.gateway.xcp_gateway", "core.server.xcp_server",
                "core.verifier.xcp_verifier"):
        pkg = mod.rsplit(".", 1)[0].replace(".", "/")
        assert (ROOT / pkg / "__init__.py").exists(), \
            f"{pkg} is not a package; uvicorn cannot import {mod}"


def test_image_runs_as_a_non_root_user():
    df = DOCKERFILE.read_text()
    assert re.search(r"^USER\s+10001", df, re.M), "image must not run as root"


def test_helm_and_compose_agree_with_the_image_contract():
    import yaml
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text())
    roles = {s["environment"]["ROLE"] for s in compose["services"].values()}
    assert roles == {"gateway", "server", "verifier"}

    for f in ("gateway", "verifier"):
        t = (ROOT / "deploy" / "helm" / "templates" / f"{f}.yaml").read_text()
        assert t.count("env:") == 1, f"{f}.yaml has duplicate env keys"
        assert f'value: "{f}"' in t, f"{f}.yaml does not set ROLE"


def test_helm_can_pin_by_digest():
    """A tag is mutable. This chart deploys the component that polices everyone
    else's supply chain, so it must be pinnable to an immutable digest."""
    t = (ROOT / "deploy" / "helm" / "templates" / "gateway.yaml").read_text()
    assert "digest" in t
    v = (ROOT / "deploy" / "helm" / "values.yaml").read_text()
    assert re.search(r"^\s*digest:", v, re.M)


def test_release_workflow_signs_what_it_publishes():
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "cosign sign" in wf, "unsigned images while demanding signed manifests"
    assert "id-token: write" in wf, "keyless signing needs OIDC"
    assert "sbom: true" in wf and "provenance: true" in wf


def test_release_gates_on_tests_and_verifies_the_result():
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "needs: test" in wf, "images must not publish ahead of the test suite"
    assert "cosign verify" in wf
    assert "refuse" in wf.lower() or "exit 1" in wf, \
        "release must fail if the gateway starts without abuse controls"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
