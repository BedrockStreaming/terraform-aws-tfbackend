resource "aws_s3_bucket" "bucket_tfstates" {
  bucket = var.bucket_tfstates_name

  force_destroy = true

  tags = merge(
    {
      "Name" = var.bucket_tfstates_name
    },
    var.tags,
  )

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_acl" "bucket_tfstates" {
  bucket = aws_s3_bucket.bucket_tfstates.bucket
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_tfstates" {
  bucket = aws_s3_bucket.bucket_tfstates.bucket
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.kms_tfstates.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "bucket_tfstates" {
  bucket = aws_s3_bucket.bucket_tfstates.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "bucket_tfstates_policy" {
  source_policy_documents = var.bucket_policy_documents

  statement {
    sid    = "Admins can do everything"
    effect = "Allow"

    principals {
      identifiers = var.administrators
      type        = "AWS"
    }

    actions = [
      "s3:DeleteBucket",
      "s3:ListBucket",
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_tfstates_name}",
      "arn:aws:s3:::${var.bucket_tfstates_name}/*",
    ]
  }

  statement {
    sid    = "Users can run Terraform"
    effect = "Allow"

    principals {
      identifiers = var.users
      type        = "AWS"
    }

    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_tfstates_name}",
      "arn:aws:s3:::${var.bucket_tfstates_name}/*",
    ]
  }

  statement {
    sid    = "Deny unencrypted object upload"
    effect = "Deny"

    principals {
      identifiers = ["*"]
      type        = "AWS"
    }

    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.bucket_tfstates_name}/*"]

    condition {
      test     = "StringNotEquals"
      values   = ["aws:kms"]
      variable = "s3:x-amz-server-side-encryption"
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_tfstates_policy" {
  bucket = aws_s3_bucket.bucket_tfstates.id
  policy = data.aws_iam_policy_document.bucket_tfstates_policy.json
}
