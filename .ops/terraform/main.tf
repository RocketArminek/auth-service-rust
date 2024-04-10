locals {
  namespace = "shared"
  app_name  = "auth-api-rust"
  app_env   = "prod"
}

module "app" {
  source           = "Arminek/app/k8s"
  version          = "1.0.2"
  app_name         = local.app_name
  namespace        = local.namespace
  app_docker_image = var.app_docker_image
  replicas         = 1
  env              = local.app_env

  hosts     = ["auth-api-rust.arminek.xyz"]
  tls_hosts = ["arminek.xyz", "*.arminek.xyz"]
  ingress_annotations = {
    "kubernetes.io/ingress.class" : "traefik"
    "cert-manager.io/cluster-issuer" : "letsencrypt"
  }

  resources_limits = {
    "cpu"    = "1"
    "memory" = "128Mi"
  }
  resources_requests = {
    "cpu"    = "250m"
    "memory" = "64Mi"
  }

  liveness_probe_path                  = "/v1/health"
  liveness_probe_initial_delay_seconds = 60
  liveness_probe_period_seconds        = 60

  readiness_probe_path                  = "/v1/health"
  readiness_probe_initial_delay_seconds = 1
  readiness_probe_period_seconds        = 10

  pdb_enabled = true

  image_pull_secrets = "github-registry"
  node_selector = {
    "purpose" = "workload"
  }
  envs_from_secrets = []
  envs_from_value = []
}
