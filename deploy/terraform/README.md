# XCP Terraform module

Declares a node, or a federation of them, as reviewable code.

```hcl
module "xcp_eu" {
  source       = "github.com/AGI-Gateway/XCP//deploy/terraform"
  image_digest = "sha256:<the digest the release workflow printed>"

  upstreams  = { research = "https://mcp.eu.internal/mcp" }
  verify_url = "http://verifier:8500"

  private_federation  = true
  peer_cidrs          = ["10.20.0.0/16", "10.30.0.0/16"]
  peer_ca_secret_name = "xcp-peer-ca"
  node_site           = "eu-west"
  residency_sites     = ["eu-west", "eu-central"]
}
```

## What it refuses at plan time

A values file cannot refuse a combination; Terraform can. Four combinations are
refused, each producing a node that looks healthy and is not:

| Refusal | Why |
|---|---|
| A weakened control not named in `acknowledge_unsafe` | Weakening a control should be a visible line in a reviewed file, not a default nobody noticed |
| `private_federation` with no `peer_cidrs` | Peering would refuse every internal address, and the symptom is peers that will not connect for no visible reason |
| `private_federation` with no `peer_ca_secret_name` | Peers would be verified against the **public** trust store while the operator believes otherwise |
| `residency_sites` with no `node_site` | A node that does not know its own site cannot tell whether a peer is inside the residency boundary, so the constraint silently permits what it forbids |

It also refuses a mutable image reference. `image_digest` must be a full
`sha256:` digest, because this chart deploys the component that polices
everyone else's supply chain and a tag means the thing you reviewed is not
necessarily the thing that runs.

`peer_cidrs` entries must be no broader than `/8`. A `/0` declaration is not a
declaration; it is disabling the egress guard with extra steps. Note that no
declaration can re-admit loopback, link-local or cloud metadata regardless —
`xcpsec.egress` checks those *before* consulting declared ranges.

## Status

**Not validated against a Terraform binary.** The HCL in this directory parses,
and the logic mirrors `ops/profiles.py`, which is tested. But `terraform
validate` and `terraform plan` have not been run against it, so semantic errors
— a wrong provider attribute, a Helm value the chart does not read — are
possible. Run `terraform init && terraform validate` before relying on it, and
please open an issue with anything it finds.

The `check` blocks need Terraform >= 1.5.
