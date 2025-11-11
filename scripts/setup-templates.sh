#!/bin/bash

# Script to fetch and setup official Nuclei templates

set -e

TEMPLATES_DIR="nuclei-templates"
REPO_URL="https://github.com/projectdiscovery/nuclei-templates.git"

echo "Setting up Nuclei templates for Breadcrumb-Pot..."

# Check if templates directory already exists
if [ -d "$TEMPLATES_DIR" ]; then
    echo "Nuclei templates directory already exists."
    read -p "Do you want to update it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Updating templates..."
        cd "$TEMPLATES_DIR"
        git pull
        cd ..
    fi
else
    echo "Cloning Nuclei templates repository..."
    git clone --depth 1 "$REPO_URL" "$TEMPLATES_DIR"
fi

echo ""
echo "Templates downloaded to: $TEMPLATES_DIR"
echo ""
echo "Available template categories:"
echo "  - nuclei-templates/http/        (HTTP-based vulnerabilities)"
echo "  - nuclei-templates/dns/         (DNS-based vulnerabilities)"
echo "  - nuclei-templates/network/     (Network/TCP vulnerabilities)"
echo "  - nuclei-templates/cves/        (CVE-specific templates)"
echo ""
echo "Update your config.yaml to point to these templates:"
echo ""
echo "templates:"
echo "  directory: nuclei-templates/http"
echo "  severities:"
echo "    - critical"
echo "    - high"
echo ""
echo "Or use CVE-specific templates:"
echo ""
echo "templates:"
echo "  directory: nuclei-templates/http/cves"
echo "  severities:"
echo "    - critical"
echo "    - high"
echo ""
echo "Setup complete!"
