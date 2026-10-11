output "image" {
  description = "The digest-pinned image this release runs."
  value       = local.image
}

output "weakened_controls" {
  description = <<-EOT
    Controls this deployment deliberately weakens. Empty on a production
    posture. Surfaced as an output so it appears in state and in any review of
    `terraform output`, not only at plan time.
  EOT
  value       = local.weakened
}

output "federation" {
  description = "The private-federation posture, for cross-checking between sites."
  value = {
    enabled         = var.private_federation
    site            = var.node_site
    peer_cidrs      = var.peer_cidrs
    residency_sites = var.residency_sites
    peer_ca         = var.peer_ca_secret_name
  }
}

output "engine" {
  description = <<-EOT
    Whether the decision engine is enabled, and its budget. Advisory only: it
    cannot change whether a request is permitted.
  EOT
  value = {
    enabled       = var.engine
    budget_micros = var.engine_budget_micros
  }
}
