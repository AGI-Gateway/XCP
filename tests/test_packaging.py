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
    # `protocol` became load-bearing when parse_ctx started importing
    # protocol.identity at module scope: without it the gateway cannot
    # authenticate anyone, and the failure is an ImportError at startup rather
    # than a guarded degrade. `ops`, `policy` and `telemetry` are copied by the
    # Dockerfile and read by the running roles, so a removal should fail here
    # rather than in production.
    needed = {"core", "trustfirewall", "security", "vault", "trust",
              "federation", "connectors", "receipts", "providers", "discovery",
              "protocol", "ops", "policy", "telemetry", "engine"}
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


def test_the_chart_can_deploy_a_private_federation():
    """
    Kubernetes across datacentres is where a private federation most likely
    runs, so the chart has to carry both settings. Checked against values.yaml
    as well as the template: a key the template reads and values.yaml does not
    declare renders cleanly and silently never reaches the pod, which surfaces
    later as peering that refuses every internal address for no visible reason.
    """
    import yaml
    t = (ROOT / "deploy" / "helm" / "templates" / "gateway.yaml").read_text()
    v = yaml.safe_load((ROOT / "deploy" / "helm" / "values.yaml").read_text())

    pf = v.get("privateFederation")
    assert isinstance(pf, dict), "values.yaml declares no privateFederation block"
    for key in ("enabled", "peerCidrs", "peerCaSecretName", "peerCaKey"):
        assert key in pf, f"values.yaml is missing privateFederation.{key}"
    assert pf["enabled"] is False, "private federation must be opt-in"

    for ref in re.findall(r"\.Values\.privateFederation\.(\w+)", t):
        assert ref in pf, \
            f"gateway.yaml reads privateFederation.{ref}, undeclared in values.yaml"

    assert "XCP_PRIVATE_PEER_CIDRS" in t and "XCP_PEER_CA_BUNDLE" in t
    # The env var points at the mount, so the two must agree.
    assert "/etc/xcp/peer-ca/" in t
    assert t.count("name: peer-ca") == 2, \
        "the peer CA secret must be both mounted and declared as a volume"


def test_the_peer_trust_anchor_is_mounted_read_only():
    t = (ROOT / "deploy" / "helm" / "templates" / "gateway.yaml").read_text()
    i = t.index("mountPath: /etc/xcp/peer-ca")
    assert "readOnly: true" in t[i:i + 80]


def test_no_image_reference_interpolates_the_raw_owner():
    """
    An OCI repository name must be lowercase, and this organisation is
    "AGI-Gateway". docker/metadata-action lowercases what it derives, so a
    build succeeds while a hand-written reference fails on an invalid
    reference -- which is exactly how v0.1.0 published an image and then
    failed to sign it, with the verify job skipped so nothing said so.

    Every image reference must come from the one lowercased value.
    """
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    for raw in ("${REGISTRY}/${IMAGE}", "env.REGISTRY }}/${{ env.IMAGE"):
        assert raw not in wf, (
            f"an image reference is built from {raw!r}, which keeps the "
            f"organisation's capital letters and is not a valid OCI reference")
    assert "tr '[:upper:]' '[:lower:]'" in wf, \
        "nothing lowercases the image name"
    # and the verify job must be able to see it
    import yaml
    d = yaml.safe_load(wf)
    assert "image" in d["jobs"]["image"]["outputs"], \
        "the image job does not publish the reference the verify job needs"


def test_the_release_verifies_before_it_claims_success():
    """
    Signing that fails must fail the release. v0.1.0 pushed an image, failed to
    sign it, and skipped verification -- so the only thing that would have
    caught an unsigned release never ran.
    """
    import yaml
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    d = yaml.safe_load(wf)
    needs = d["jobs"]["verify"]["needs"]
    assert needs == "image" or "image" in needs, \
        "the verify job does not depend on the build, so it can run without it"
    assert "cosign verify" in wf
    sign = [s for j in d["jobs"].values() for s in j.get("steps", [])
            if "cosign sign" in str(s.get("run", ""))]
    assert sign, "the release does not sign"
    for s in sign:
        assert "continue-on-error" not in s, \
            "a failed signature would not fail the release"


def test_release_workflow_signs_what_it_publishes():
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "cosign sign" in wf, "unsigned images while demanding signed manifests"
    assert "id-token: write" in wf, "keyless signing needs OIDC"
    assert "sbom: true" in wf and "provenance: true" in wf


def test_every_published_artifact_is_gated_on_the_sdk_vectors():
    """
    A package whose protocol primitives disagree with the gateway breaks at the
    integration boundary, against a gateway the integrator does not control --
    and the failure looks like the gateway's fault. So nothing publishes until
    every port reproduces the committed vectors.
    """
    import yaml
    d = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    jobs = d["jobs"]
    assert "ports" in jobs, "the release does not check the SDK ports"

    steps = " ".join(str(s.get("run", "")) for s in jobs["ports"]["steps"])
    for runner in ("python -m sdk", "vectors.mjs", "go test ./sdk/go"):
        assert runner in steps, f"the ports job does not run {runner!r}"
    assert "generate-sdk-contract.py --check" in steps, \
        "the ports job does not check the contract against its sources"

    for name in ("pypi", "npm", "gomodule", "image"):
        needs = jobs[name]["needs"]
        needs = [needs] if isinstance(needs, str) else needs
        assert "ports" in needs, (
            f"the {name!r} job does not depend on the SDK vectors, so it can "
            f"publish an artifact that disagrees with the protocol")


def test_publishing_uses_oidc_rather_than_long_lived_tokens():
    """
    PyPI Trusted Publishing needs no API token, so there is none to leak or
    rotate. npm still needs a token but gets provenance from the same OIDC
    identity. A project that enforces signed, digest-pinned manifests on
    everyone else's tools should not be publishing unattested packages.
    """
    import yaml
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    d = yaml.safe_load(wf)

    assert d["jobs"]["pypi"]["permissions"]["id-token"] == "write"
    assert "pypa/gh-action-pypi-publish" in wf
    assert "attestations: true" in wf, "PyPI distributions are not attested"

    assert d["jobs"]["npm"]["permissions"]["id-token"] == "write"
    assert "--provenance" in wf, "npm package is published without provenance"

    # A protected environment, so a tag alone cannot publish.
    for name in ("pypi", "npm"):
        assert d["jobs"][name].get("environment") == "release", (
            f"the {name!r} job is not bound to a protected environment")


def test_the_wheel_is_verified_before_publication_not_after():
    """
    The zero-dependency claim is checked against the BUILT ARTIFACT, because
    that is where the keccak fallback defect was caught and it was invisible
    from the source tree.
    """
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "pip list --format=freeze" in wf
    assert "python -m sdk" in wf
    i = wf.index("must install with no dependencies")
    j = wf.index("pypa/gh-action-pypi-publish")
    assert i < j, "the wheel is published before it is verified"


def test_release_gates_on_tests_and_verifies_the_result():
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "needs: test" in wf, "images must not publish ahead of the test suite"
    assert "cosign verify" in wf
    assert "refuse" in wf.lower() or "exit 1" in wf, \
        "release must fail if the gateway starts without abuse controls"


def test_the_terraform_module_refuses_the_four_bad_combinations():
    """
    A values file cannot refuse a combination; Terraform can. These four each
    produce a node that looks healthy and is not, so the module must stop them
    at plan time rather than apply cleanly.

    Asserted against the text rather than a parsed AST so this test needs no
    HCL parser — the dependency-light CI job runs it.
    """
    tf = (ROOT / "deploy" / "terraform" / "main.tf").read_text()
    for name in ("controls_are_acknowledged",
                 "acknowledgements_are_not_stale",
                 "private_federation_is_completely_configured",
                 "residency_has_a_vantage_point"):
        assert f'check "{name}"' in tf, f"the module lost its {name!r} check"
    assert tf.count("assert {") >= 5, "a refusal has lost its assertion"


def test_the_terraform_module_will_not_accept_a_mutable_image():
    v = (ROOT / "deploy" / "terraform" / "variables.tf").read_text()
    assert "sha256:[0-9a-f]{64}" in v, (
        "image_digest no longer requires a full digest; a tag means the thing "
        "you reviewed is not necessarily the thing that runs")


def test_the_terraform_module_rejects_an_overbroad_peer_cidr():
    v = (ROOT / "deploy" / "terraform" / "variables.tf").read_text()
    assert ">= 8" in v, (
        "peer_cidrs no longer enforces a minimum prefix; a /0 declaration is "
        "disabling the egress guard with extra steps")


def test_the_terraform_module_states_it_is_unvalidated():
    """
    No Terraform binary was available when this module was written, so only
    its HCL syntax was checked. Claiming more than was verified is the failure
    mode worth a test of its own.
    """
    readme = (ROOT / "deploy" / "terraform" / "README.md").read_text()
    assert "Not validated against a Terraform binary" in readme


#: Values declared in values.yaml that no template reads, and why that is
#: tolerated. An entry here is a promise an operator can set and nothing will
#: happen, so the list is short and each item names what is missing.
#:
#: `server.*` used to be on this list: values.yaml declared server.enabled and
#: there was no server template, so turning it on did nothing, silently. That
#: is now templates/server.yaml.
KNOWN_UNREAD_VALUES = {
    # Needs a ServiceMonitor resource and the Prometheus Operator CRDs. The
    # gateway already serves /metrics, so scraping works without it.
    "serviceMonitor", "serviceMonitor.enabled",
    # Declarative trust tier. The lattice cell is established per session from
    # the agent's and human's credentials, not from chart config, so there is
    # nothing for a template to render this into. Kept because removing a key
    # breaks existing values files.
    "trust", "trust.agent", "trust.human",
}


def _chart_value_keys() -> set:
    import yaml
    v = yaml.safe_load((ROOT / "deploy" / "helm" / "values.yaml").read_text())

    def flat(d, prefix=""):
        for k, val in (d or {}).items():
            name = f"{prefix}.{k}" if prefix else k
            # Yield the key itself whether or not it is an empty container. An
            # earlier version of this walk recursed into dicts without
            # yielding them, so `upstreams: {}` looked undeclared -- which is
            # a bug in the checker that reads as a bug in the chart.
            yield name
            if isinstance(val, dict) and val:
                yield from flat(val, name)

    return set(flat(v))


def _chart_values_read() -> set:
    out = set()
    for t in (ROOT / "deploy" / "helm" / "templates").glob("*.yaml"):
        out |= set(re.findall(r"\.Values\.([A-Za-z0-9_.]+)", t.read_text()))
    return {r.rstrip(".") for r in out}


def test_every_value_a_template_reads_is_declared():
    """
    The dangerous direction. A key the template reads and values.yaml does not
    declare renders cleanly and silently never reaches the pod, which surfaces
    later as a control the operator believes is on and is not.
    """
    missing = sorted(_chart_values_read() - _chart_value_keys())
    assert not missing, (
        f"templates read these and values.yaml does not declare them: "
        f"{missing}. Each one renders as empty and silently never reaches the "
        f"pod.")


def test_every_declared_value_is_read_by_a_template():
    """
    The other direction. A value nobody reads is a setting an operator can
    change with no effect -- less dangerous than a missing control, and still
    a lie in a file people configure from.
    """
    keys = _chart_value_keys()
    read = _chart_values_read()
    unread = sorted(
        k for k in keys
        if k not in read
        and not any(r.startswith(k + ".") for r in read)
        and not any(k.startswith(r + ".") for r in read)
        and k not in KNOWN_UNREAD_VALUES)
    assert not unread, (
        f"values.yaml declares these and no template reads them: {unread}. "
        f"Either wire them up or add them to KNOWN_UNREAD_VALUES with a note "
        f"saying what is missing.")


def test_the_chart_can_deploy_every_role_the_image_supports():
    """
    The image has three roles and the entrypoint fails loudly on a fourth. The
    chart could deploy two of them while declaring values for the third.
    """
    templates = {t.stem for t in
                 (ROOT / "deploy" / "helm" / "templates").glob("*.yaml")}
    for role in ("gateway", "server", "verifier"):
        assert role in templates, f"the chart has no template for {role!r}"
        t = (ROOT / "deploy" / "helm" / "templates" / f"{role}.yaml").read_text()
        assert f'value: "{role}"' in t, f"{role}.yaml does not set ROLE"


def test_the_server_is_not_exposable_as_a_load_balancer():
    """
    The server is reached through the gateway. A configurable service type
    would let an operator put an MCP endpoint on the internet with
    REQUIRE_VERIFIED as the only thing between it and an anonymous caller.
    """
    t = (ROOT / "deploy" / "helm" / "templates" / "server.yaml").read_text()
    assert "type: ClusterIP" in t
    assert ".Values.server.service.type" not in t


def test_the_chart_renders_the_abuse_controls_explicitly():
    """
    Rendered unconditionally rather than behind an `if`, so `kubectl describe`
    states the posture instead of relying on the image default.
    """
    t = (ROOT / "deploy" / "helm" / "templates" / "gateway.yaml").read_text()
    for var in ("XCP_RATE_LIMIT", "XCP_LIMIT_FAIL_OPEN",
                "XCP_NODE_RECORD_PUBLIC"):
        assert var in t, f"gateway.yaml does not render {var}"


def test_the_engine_is_off_by_default_in_the_chart():
    import yaml
    v = yaml.safe_load((ROOT / "deploy" / "helm" / "values.yaml").read_text())
    assert v["engine"]["enabled"] is False, "the decision engine must be opt-in"
    t = (ROOT / "deploy" / "helm" / "templates" / "gateway.yaml").read_text()
    assert "XCP_ENGINE" in t and ".Values.engine.enabled" in t


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
