# XCP Terraform module.
#
# Wraps the Helm chart so a federation can be declared as code: several nodes
# across datacentres, each with its own site, residency policy and peer set,
# reviewed as a diff rather than applied by hand.
#
# WHAT THIS MODULE REFUSES
#
# The cross-variable checks below are the reason this exists rather than a
# README telling people which Helm values to set. Terraform can refuse a
# combination at plan time; a values file cannot. Four combinations are refused,
# each of which produces a node that looks healthy and is not:
#
#   1. Weakening a control without naming it in acknowledge_unsafe.
#   2. Private federation with no declared peer CIDRs — peering would refuse
#      every internal address and the operator would see only mysterious
#      failures.
#   3. Private federation with no internal CA — peers would be verified against
#      the public trust store while the operator believes otherwise.
#   4. Residency sites declared with no node site — the node cannot tell
#      whether it is inside its own residency boundary, so the constraint
#      silently applies to nothing.

terraform {
  required_version = ">= 1.5"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }
}

locals {
  # ── refusals, as assertions ─────────────────────────────────────────────
  #
  # Expressed as locals with `precondition`-style checks so the message names
  # the fix rather than the rule.

  weakened = compact([
    var.posture == "observe" ? "posture" : "",
    var.rate_limit ? "" : "limits",
    var.limit_fail_open ? "limit_fail_open" : "",
    var.node_record_public ? "public_node_record" : "",
  ])

  unacknowledged = setsubtract(toset(local.weakened), toset(var.acknowledge_unsafe))
  stale_acks     = setsubtract(toset(var.acknowledge_unsafe), toset(local.weakened))

  image = "ghcr.io/agi-gateway/xcp@${var.image_digest}"

  # Shapes matter here, and getting one wrong is silent. The chart renders
  # `upstreams` with `toJson` (so it wants the MAP, not a JSON string) and
  # renders `residencySites` and `peerCidrs` with `join ","` (so they want
  # LISTS, not pre-joined strings). Passing a string where the template calls
  # `join` renders something subtly wrong rather than failing.
  #
  # Every key below is read by a template. tests/test_packaging.py checks that
  # correspondence in both directions, because a value no template reads is a
  # setting an operator can change with no effect.
  values = {
    image = {
      repository = "ghcr.io/agi-gateway/xcp"
      digest     = var.image_digest
    }
    gateway = {
      replicas         = var.replicas
      posture          = var.posture
      security         = "1"
      upstreams        = var.upstreams
      rateLimit        = var.rate_limit
      limitFailOpen    = var.limit_fail_open
      nodeRecordPublic = var.node_record_public
      nodeSite         = var.node_site
      residencySites   = var.residency_sites
    }
    # The chart derives XCP_VERIFY_URL from the in-cluster verifier service, so
    # an explicit URL is only needed when pointing at one outside the release.
    verifier = {
      enabled = var.verify_url == ""
    }
    engine = {
      enabled      = var.engine
      budgetMicros = var.engine_budget_micros
    }
    privateFederation = {
      enabled          = var.private_federation
      peerCidrs        = var.peer_cidrs
      peerCaSecretName = var.peer_ca_secret_name
      peerCaKey        = var.peer_ca_key
    }
  }
}

# Terraform has no standalone `assert`, so the refusals are expressed as a
# null_resource-free check block (Terraform >= 1.5). A failing check stops the
# plan with the message, which is the behaviour we want: the operator sees the
# reason, not a cleanly applied open relay.
check "controls_are_acknowledged" {
  assert {
    condition = length(local.unacknowledged) == 0
    error_message = <<-EOT
      This deployment weakens controls that are not named in
      acknowledge_unsafe: ${join(", ", local.unacknowledged)}.

      Add them to acknowledge_unsafe to state the decision explicitly, or
      change the setting. The point is that weakening a control should be a
      visible line in a reviewed file rather than a default nobody noticed.
    EOT
  }
}

check "acknowledgements_are_not_stale" {
  assert {
    condition = length(local.stale_acks) == 0
    error_message = <<-EOT
      acknowledge_unsafe names controls that are not actually weakened:
      ${join(", ", local.stale_acks)}.

      A stale acknowledgement reads as approval of something that is not
      happening, which makes the list useless as a thing to review. Remove
      them.
    EOT
  }
}

check "private_federation_is_completely_configured" {
  assert {
    condition = !var.private_federation || length(var.peer_cidrs) > 0
    error_message = <<-EOT
      private_federation is true but peer_cidrs is empty.

      Peering would then refuse every internal address, and the symptom is
      peers that will not connect for no visible reason. Declare the ranges
      that hold your peers.
    EOT
  }

  assert {
    condition = !var.private_federation || var.peer_ca_secret_name != ""
    error_message = <<-EOT
      private_federation is true but peer_ca_secret_name is empty.

      Peers would be verified against the PUBLIC trust store while you believe
      they are verified against your own CA. Supply the secret holding your
      internal CA bundle.
    EOT
  }
}

check "residency_has_a_vantage_point" {
  assert {
    condition = length(var.residency_sites) == 0 || var.node_site != ""
    error_message = <<-EOT
      residency_sites is set but node_site is empty.

      A node that does not know its own site cannot tell whether a peer is
      inside the residency boundary, so the constraint applies to nothing and
      silently permits what it was written to forbid. Set node_site.
    EOT
  }
}

resource "helm_release" "xcp" {
  name      = var.release_name
  namespace = var.namespace
  chart     = "${path.module}/../helm"

  create_namespace = true
  atomic           = true
  wait             = true

  values = [yamlencode(local.values)]
}
