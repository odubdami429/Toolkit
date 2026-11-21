# Remote state in S3, configured at init time so nothing account-specific lives in the repo:
#
#   cp backend.hcl.example backend.hcl   # fill in bucket, key and region
#   terraform init -backend-config=backend.hcl
#
# Remove this block to use local state instead.
terraform {
  backend "s3" {}
}
