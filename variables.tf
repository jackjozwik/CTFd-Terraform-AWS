variable "access_key" {
  description = "The access key for API operations"
  type        = string
}

variable "secret_key" {
  description = "The secret key for API operations"
  type        = string
}

variable "region" {
  description = "The region where AWS operations will take place"
  type        = string
  default     = "us-east-1"
}