// Name of the s3 bucket
variable "bucket_tfstates_name" {
  type = string
}

// Region where the objects will be deployed
variable "deploy_region" {
  type = string
}

// List of infrastructure administrators
variable "administrators" {
  type = list(string)
}

// List of Terraform users
variable "users" {
  type = list(string)
}

variable "kms_policy_documents" {
  type        = list(string)
  description = "additional KMS policy documents (in JSON)"
  default     = []
}

variable "bucket_policy_documents" {
  type        = list(string)
  description = "additional Bucket policy documents (in JSON)"
  default     = []
}

// Tags to apply on s3_bucket
variable "tags" {
  type = map(string)
}

