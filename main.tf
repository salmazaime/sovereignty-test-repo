# main.tf -- COMPLIANT scenario: adequate destination, non-OIV company
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "acme-eu-reports"
  region = "eu-west-3"
  tags = {
    owner       = "finance-team"
    environment = "prod"
  }
}

resource "aws_s3_bucket_public_access_block" "compliant_bucket" {
  bucket                  = aws_s3_bucket.compliant_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# NON-COMPLIANT scenario: non-adequate destination -> expect REVIEW
resource "aws_s3_bucket" "review_bucket" {
  bucket = "acme-us-customer-export"
  region = "us-east-1"
}

resource "aws_s3_bucket_public_access_block" "review_bucket" {
  bucket                  = aws_s3_bucket.review_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
