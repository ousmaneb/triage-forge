# Deploying to AWS

Resources: ECR repository, ECS Fargate service behind an Application Load Balancer, Secrets Manager entries for the Anthropic API key and webhook token, a CloudWatch log group, and (optionally) an IAM role GitHub Actions assumes through OIDC.

## First deployment

```bash
cd deploy/terraform
terraform init
terraform apply -target=aws_ecr_repository.app          # the repository has to exist before the first push

# Fargate runs x86_64, so build for amd64 on Apple silicon
REPO=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
docker buildx build --platform linux/amd64 -t "$REPO:bootstrap" --push ../..

terraform apply -var github_repo=ousmaneb/triage-forge

aws secretsmanager put-secret-value --secret-id triage-forge/anthropic-api-key --secret-string "$ANTHROPIC_API_KEY"
aws secretsmanager put-secret-value --secret-id triage-forge/webhook-token --secret-string "$(openssl rand -hex 24)"
aws ecs update-service --cluster triage-forge --service triage-forge --force-new-deployment

curl "$(terraform output -raw service_url)/health"
```

## Later deployments

In the GitHub repository, set the secret `AWS_DEPLOY_ROLE_ARN` (from `terraform output deploy_role_arn`), the variables `AWS_REGION` and `SERVICE_URL`, and create an environment named `production`. Pushing a tag such as `v0.2.0` runs the tests and evaluation gate, builds and pushes the image, registers a new task definition, waits for the service to stabilize, and calls `/health`. The ECS deployment circuit breaker rolls back a release that fails its health checks.

## Cost

One task at 0.5 vCPU / 1 GB is about $18 per month, and the load balancer about $17 plus traffic. `terraform apply -var desired_count=0` stops the task; `terraform destroy` removes everything.
