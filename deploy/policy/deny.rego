package main

name = input.metadata.name

deny[msg] {
  input.kind = "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg = sprintf("Containers must not run as root in Deployment %s", [name])
}

required_deployment_selectors {
  input.spec.selector.matchLabels.app
  input.spec.selector.matchLabels.version
}

deny[msg] {
  input.kind = "Deployment"
  not required_deployment_selectors

  msg = sprintf("Deployment %s must provide app/release labels for pod selectors", [name])
}
