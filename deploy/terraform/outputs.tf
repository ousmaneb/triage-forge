output "service_url" {
  value = "${local.https ? "https" : "http"}://${aws_lb.app.dns_name}"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "deploy_role_arn" {
  value = var.github_repo != "" ? aws_iam_role.deploy[0].arn : ""
}

output "anthropic_secret_id" {
  value = aws_secretsmanager_secret.anthropic.name
}

output "webhook_secret_id" {
  value = aws_secretsmanager_secret.webhook.name
}
