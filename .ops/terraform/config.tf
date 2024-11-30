terraform {
  backend "remote" {
    organization = "rocket-arminek"

    workspaces {
      name = "auth-api-rust-demo"
    }
  }
}
