#!/bin/bash

# Terraform quality checks script
# Usage: ./scripts/terraform-check.sh [format|validate|lint|docs|security|all]

set -e

ACTION=${1:-all}

check_tools() {
    echo "Checking required tools..."
    command -v terraform >/dev/null 2>&1 || { echo "Error: terraform not found"; exit 1; }
    command -v tflint >/dev/null 2>&1 || { echo "Error: tflint not found. Install: https://github.com/terraform-linters/tflint"; exit 1; }
    command -v terraform-docs >/dev/null 2>&1 || { echo "Error: terraform-docs not found. Install: https://terraform-docs.io/"; exit 1; }
    command -v checkov >/dev/null 2>&1 || { echo "Error: checkov not found. Install: pip install checkov"; exit 1; }
    command -v trivy >/dev/null 2>&1 || { echo "Error: trivy not found. Install: https://aquasecurity.github.io/trivy/"; exit 1; }
    echo "All tools available ✓"
}

terraform_format() {
    echo "🔧 Formatting Terraform files..."
    terraform fmt -recursive terraform/
    echo "Format complete ✓"
}

terraform_validate() {
    echo "✅ Validating Terraform configuration..."
    
    for env in dev prod; do
        echo "Validating $env environment..."
        cd terraform/environments/$env
        terraform init -backend=false
        terraform validate
        cd ../../..
    done
    
    echo "Validation complete ✓"
}

terraform_lint() {
    echo "🔍 Running TFLint..."
    
    tflint --init
    tflint --config=.tflint.hcl terraform/
    
    for env in dev prod; do
        echo "Linting $env environment..."
        cd terraform/environments/$env
        tflint --config=../../.tflint.hcl .
        cd ../../..
    done
    
    echo "Linting complete ✓"
}

terraform_docs() {
    echo "📚 Generating Terraform documentation..."
    
    terraform-docs terraform/
    terraform-docs terraform/environments/dev/
    terraform-docs terraform/environments/prod/
    
    echo "Documentation complete ✓"
}

terraform_security() {
    echo "🔒 Running security checks..."
    
    echo "Running Checkov..."
    checkov -d terraform/ --framework terraform --skip-check CKV_AWS_79,CKV_AWS_115,CKV_AWS_116,CKV_AWS_117,CKV_AWS_173,CKV_AWS_260
    
    echo "Running Trivy..."
    trivy config terraform/ --severity HIGH,CRITICAL
    
    echo "Security checks complete ✓"
}

case $ACTION in
    format)
        check_tools
        terraform_format
        ;;
    validate)
        check_tools
        terraform_validate
        ;;
    lint)
        check_tools
        terraform_lint
        ;;
    docs)
        check_tools
        terraform_docs
        ;;
    security)
        check_tools
        terraform_security
        ;;
    all)
        check_tools
        terraform_format
        terraform_validate
        terraform_lint
        terraform_docs
        terraform_security
        echo ""
        echo "🎉 All Terraform checks completed successfully!"
        ;;
    *)
        echo "Usage: $0 [format|validate|lint|docs|security|all]"
        echo ""
        echo "Commands:"
        echo "  format    - Format Terraform files"
        echo "  validate  - Validate Terraform configuration"
        echo "  lint      - Run TFLint checks"
        echo "  docs      - Generate documentation"
        echo "  security  - Run security scans"
        echo "  all       - Run all checks (default)"
        exit 1
        ;;
esac