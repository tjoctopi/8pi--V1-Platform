# Remote state in S3 with DynamoDB locking.
# Partial config: supply bucket/table at init time so this env stays reusable
# and its state key is isolated from the console env.
#
#   terraform init -backend-config=backend.hcl
#
terraform {
  backend "s3" {
    key = "8pi/engine-dev/terraform.tfstate"
  }
}
