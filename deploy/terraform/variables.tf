# XCP Terraform module — inputs, with the unsafe ones refused at plan time.
#
# WHY VALIDATION LIVES HERE
#
# ops/profiles.py refuses a profile that weakens a control without a stated
# reason, and ops/config.py marks which settings weaken one. A Terraform module
# that accepted anything would be a third way to configure a node, with none of
# that checking — and it would be the way most production deployments actually
# happen.
#
# So the same rules are enforced at plan time. A `terraform plan` that would
# produce an open relay fails with the reason, rather than applying cleanly and
# leaving the operator to discover it.

variable "namespace" {
  type        = string
  description = "Kubernetes namespace for the release."
  default     = "xcp"
}

variable "release_name" {
  type        = string
  description = "Helm release name."
  default     = "xcp"
}

variable "image_digest" {
  type        = string
  description = <<-EOT
    Immutable image digest, e.g. sha256:abc123... A tag is deliberately not
    accepted: this chart deploys the component that polices everyone else's
    supply chain, and a mutable reference means the thing you reviewed is not
    necessarily the thing that runs.
  EOT

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be a full sha256 digest (sha256: followed by 64 hex characters). A tag is not accepted; pin the digest the release workflow printed."
  }
}

variable "posture" {
  type        = string
  description = "enforce | observe. Observe logs decisions without blocking them."
  default     = "enforce"

  validation {
    condition     = contains(["enforce", "observe"], var.posture)
    error_message = "posture must be enforce or observe."
  }
}

variable "acknowledge_unsafe" {
  type        = list(string)
  description = <<-EOT
    Controls this deployment deliberately weakens, named explicitly. A setting
    that weakens a control must appear here or the plan fails.

    This exists so that weakening a control is a visible line in a reviewed
    file rather than a default nobody noticed. Accepted values:
      "posture"            running in observe; the node refuses nothing
      "limits"             abuse controls off; an open relay to strangers
      "limit_fail_open"    serve traffic when the limiter itself fails
      "public_node_record" full node record served to anyone
  EOT
  default     = []

  validation {
    condition = alltrue([
      for a in var.acknowledge_unsafe :
      contains(["posture", "limits", "limit_fail_open", "public_node_record"], a)
    ])
    error_message = "acknowledge_unsafe may only contain: posture, limits, limit_fail_open, public_node_record."
  }
}

variable "rate_limit" {
  type        = bool
  description = "Abuse controls. False on a node reachable by strangers makes it an open relay."
  default     = true
}

variable "limit_fail_open" {
  type        = bool
  description = "Serve traffic if the limiter itself fails. Turns any limiter outage into an unmetered window."
  default     = false
}

variable "node_record_public" {
  type        = bool
  description = "Serve the FULL node record to anyone, even in a closed cluster."
  default     = false
}

variable "upstreams" {
  type        = map(string)
  description = "Server name to MCP URL, e.g. { research = \"https://mcp.internal/mcp\" }."
  default     = {}

  validation {
    condition = alltrue([
      for u in values(var.upstreams) : startswith(u, "https://") || startswith(u, "http://127.0.0.1") || startswith(u, "http://localhost")
    ])
    error_message = "An upstream must be https://, or http:// on loopback for local development. Plain HTTP to a remote host is refused: an internal network is exactly where an attacker with a foothold is positioned to read and rewrite traffic."
  }
}

variable "verify_url" {
  type        = string
  description = "Verifier URL for ERC-8004 identity lookups."
  default     = ""
}

# ── private federation ────────────────────────────────────────────────────

variable "private_federation" {
  type        = bool
  description = "Enable peering across datacentres. Opt-in."
  default     = false
}

variable "peer_cidrs" {
  type        = list(string)
  description = <<-EOT
    Internal ranges that may hold federation peers, e.g. ["10.20.0.0/16"].

    Narrower than permitting all private space, and an undeclared range is
    still refused. Note that no declaration can re-admit loopback, link-local
    or cloud metadata: xcpsec.egress checks those BEFORE consulting declared
    ranges, which is the whole reason declaring a CIDR is safer than disabling
    the guard.
  EOT
  default     = []

  validation {
    # A /0 or /1 declaration is "allow everything" wearing a CIDR's clothes.
    # The engine enforces a minimum prefix of /8 for v4; this refuses the
    # obviously-wrong cases at plan time with a better message than the node
    # can give at startup.
    condition = alltrue([
      for c in var.peer_cidrs :
      can(cidrhost(c, 0)) && tonumber(split("/", c)[1]) >= 8
    ])
    error_message = "Each peer CIDR must be valid and no broader than /8. A /0 declaration is not a declaration; it is disabling the egress guard with extra steps."
  }
}

variable "peer_ca_secret_name" {
  type        = string
  description = <<-EOT
    Kubernetes secret holding the internal CA bundle for peer connections.

    This REPLACES the public trust store rather than adding to it. That is the
    point: an internal CA is what makes a private peer verifiable, and adding
    it to the public set would leave the node trusting every public root as
    well.
  EOT
  default     = ""
}

variable "peer_ca_key" {
  type        = string
  description = "Key within the peer CA secret."
  default     = "ca.crt"
}

variable "node_site" {
  type        = string
  description = <<-EOT
    This node's site, e.g. eu-west. A peer elsewhere is priced at
    CROSS_SITE_COST and can still win on cost: locality is a COST.
  EOT
  default     = ""
}

variable "residency_sites" {
  type        = list(string)
  description = <<-EOT
    Sites data may reach. Unlike locality this is a CONSTRAINT: a site outside
    this set is inadmissible at any price. A constraint which can be outweighed
    is a preference wearing a constraint's name.
  EOT
  default     = []
}

# ── the decision engine ───────────────────────────────────────────────────

variable "engine" {
  type        = bool
  description = <<-EOT
    Enable the self-hosted decision engine: a local classifier that estimates
    complexity and risk so cheap requests can take a cheap route.

    Advisory only. It cannot change whether a request is permitted, in either
    direction, and a refusal never cites it. Unlike the security layer, the
    gateway does not refuse to start when this is on and the engine is
    unavailable: an absent optimisation is not an absent control.
  EOT
  default     = false
}

variable "engine_budget_micros" {
  type        = number
  description = "Per-request classification budget. A tier costing more than what remains is skipped."
  default     = 2000

  validation {
    condition     = var.engine_budget_micros >= 0 && var.engine_budget_micros <= 1000000
    error_message = "engine_budget_micros must be between 0 and 1000000. A classification budget above a second is not a budget."
  }
}

variable "replicas" {
  type        = number
  description = "Gateway replica count."
  default     = 2

  validation {
    condition     = var.replicas >= 1
    error_message = "replicas must be at least 1."
  }
}
