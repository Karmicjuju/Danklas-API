# Danklas-API Terraform Root Module

This directory contains the root Terraform module for provisioning Danklas-API infrastructure.

## Usage

1. Update the `backend` block in `main.tf` with your S3 bucket and region for remote state.
2. Run `terraform init` to initialize the backend.
3. Run `terraform plan` and `terraform apply` to provision resources.

## Requirements
- Terraform >= 1.3.0
- AWS provider >= 5.0

## Structure
- `main.tf` — Root module, AWS provider, backend config 