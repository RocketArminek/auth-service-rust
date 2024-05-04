locals {
  namespace = "4ecommerce"
  app_name  = "auth-api"
  app_env   = "prod"
}

module "app_4ecommerce" {
  depends_on = [kubernetes_secret.app_4ecommerce]
  source           = "Arminek/app/k8s"
  version          = "1.1.0"
  app_name         = local.app_name
  namespace        = local.namespace
  app_docker_image = var.app_docker_image
  replicas         = 1
  env              = local.app_env

  ingress_enabled = false

  resources_limits = {
    "cpu"    = "350m"
    "memory" = "64Mi"
  }

  resources_requests = {
    "cpu"    = "250m"
    "memory" = "32Mi"
  }

  liveness_probe_path                  = "/v1/health"
  liveness_probe_initial_delay_seconds = 60
  liveness_probe_period_seconds        = 120

  readiness_probe_path                  = "/v1/health"
  readiness_probe_initial_delay_seconds = 1
  readiness_probe_period_seconds        = 60

  pdb_enabled = true

  image_pull_secrets = "github-registry"
  image_pull_policy = "Always"
  node_selector = {
    "purpose" = "workload"
  }
  envs_from_secrets = [
    {
      name        = "DATABASE_USER"
      secret_name = "mysql-secret"
      secret_key  = "user"
    },
    {
      name        = "DATABASE_PASSWORD"
      secret_name = "mysql-secret"
      secret_key  = "password"
    },
    {
      name        = "SECRET"
      secret_name = local.app_name
      secret_key  = "secret"
    }
  ]
  envs_from_value = [
    {
      name  = "DATABASE_NAME"
      value = "auth_service_4ecommerce"
    },
    {
      name  = "DATABASE_HOST"
      value = "percona-mysql-cluster-haproxy.databases.svc.cluster.local"
    },
    {
      name  = "DATABASE_PORT"
      value = "3306"
    },
    {
      name  = "PASSWORD_HASHING_SCHEME"
      value = "bcrypt_low"
      //bcrypt_low, bcrypt, argon2 -> Warning: Changing this value will increase cpu and memory usage.
      //bcrypt_low is the most efficient hashing scheme
      //bcrypt is more cpu intensive than bcrypt_low
      //argon2 is the most memory & cpu intensive hashing scheme it requires at least 1GB of memory per pod
    }
  ]
}

resource "random_password" "secret_4ecommerce" {
  length = 24
  special = true
}

resource "kubernetes_secret" "app_4ecommerce" {
  depends_on = [random_password.secret_4ecommerce]
  metadata {
    name = local.app_name
    namespace = local.namespace
  }

  data = {
    secret = random_password.secret_4ecommerce.result
  }
}

resource "kubernetes_manifest" "routing_4ecommerce" {
  manifest = {
    apiVersion = "traefik.containo.us/v1alpha1"
    kind       = "IngressRoute"
    metadata = {
      name      = local.app_name
      namespace = local.namespace
    }
    spec = {
      entryPoints = ["websecure", "web"]
      routes = [
        {
          kind = "Rule"
          match = "Host(`auth-4ecommerce.arminek.xyz`) && PathPrefix(`/`)"
          services = [
            {
              name = local.app_name
              port = 80
            }
          ]
        }
      ]
      tls = {
        secretName = "arminek-cert-tls"
        domains = [
          {
            main = "arminek.xyz"
            sans = ["*.arminek.xyz"]
          }
        ]
      }
    }
  }
}
