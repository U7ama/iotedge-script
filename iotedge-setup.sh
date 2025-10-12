#!/bin/bash

# =========================================================
# Azure IoT Edge One-Command Setup Script
# =========================================================

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default provisioning method
PROVISIONING_METHOD="connection-string"

# Parse command arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --connection-string)
      CONNECTION_STRING="$2"
      shift 2
      ;;
    --provisioning-method)
      PROVISIONING_METHOD="$2"
      shift 2
      ;;
    --iothub-hostname)
      IOTHUB_HOSTNAME="$2"
      shift 2
      ;;
    --device-id)
      DEVICE_ID="$2"
      shift 2
      ;;
    --edge-ca-name)
      EDGE_CA_NAME="$2"
      shift 2
      ;;
    --clean)
      CLEAN_INSTALL=true
      shift 1
      ;;
    --callback-url)
      CALLBACK_URL="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options for Connection String Provisioning (default):"
      echo "  --connection-string \"HostName=...\"  Your IoT Edge device connection string."
      echo ""
      echo "Options for X.509 Certificate Provisioning:"
      echo "  --provisioning-method x509            Set provisioning method to X.509."
      echo "  --iothub-hostname \"my-hub.azure-devices.net\" Your IoT Hub hostname."
      echo "  --device-id \"my-edge-device\"        The device ID for your Edge device."
      echo "  --edge-ca-name \"my-edge-ca\"         (Optional) Name for the Edge CA certificate."
      echo ""
      echo "Other Options:"
      echo "  --clean                                 Perform a clean uninstall before setup."
      echo "  --callback-url \"https://...\"        URL to report installation status."
      echo "  --help                                  Show this help message."
      exit 0
      ;;
    *)
      echo "Unknown parameter: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# --- Input Validation and Processing ---

if [ "$PROVISIONING_METHOD" = "connection-string" ]; then
  # If no connection string is provided, prompt the user for one
  if [ -z "$CONNECTION_STRING" ]; then
    echo -e "${YELLOW}No connection string provided.${NC}"
    echo -e "Please enter your IoT Edge device connection string:"
    read -p "> " CONNECTION_STRING
    
    # Check if the user provided a connection string
    if [ -z "$CONNECTION_STRING" ]; then
      echo -e "${RED}Error: Connection string is required for this provisioning method.${NC}"
      echo -e "You can get it from Azure Portal > IoT Hub > IoT Edge > Your device > Connection string"
      exit 1
    fi
  fi
elif [ "$PROVISIONING_METHOD" = "x509" ]; then
  # Prompt for required X.509 parameters if not provided
  if [ -z "$IOTHUB_HOSTNAME" ]; then
    echo -e "${YELLOW}No IoT Hub hostname provided.${NC}"
    read -p "Please enter your IoT Hub hostname (e.g., my-hub.azure-devices.net): " IOTHUB_HOSTNAME
    if [ -z "$IOTHUB_HOSTNAME" ]; then
      echo -e "${RED}Error: IoT Hub hostname is required for X.509 provisioning.${NC}"
      exit 1
    fi
  fi
  if [ -z "$DEVICE_ID" ]; then
    echo -e "${YELLOW}No Device ID provided.${NC}"
    read -p "Please enter your IoT Edge Device ID: " DEVICE_ID
    if [ -z "$DEVICE_ID" ]; then
      echo -e "${RED}Error: Device ID is required for X.509 provisioning.${NC}"
      exit 1
    fi
  fi
  # Use device ID as edge CA name if not provided
  if [ -z "$EDGE_CA_NAME" ]; then
    EDGE_CA_NAME="${DEVICE_ID}-ca"
    echo -e "${GREEN}[INFO]${NC} Using '${EDGE_CA_NAME}' as the Edge CA certificate name."
  fi
else
  echo -e "${RED}Error: Invalid provisioning method '$PROVISIONING_METHOD'. Use 'connection-string' or 'x509'.${NC}"
  exit 1
fi

# Function for printing status messages
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Validate connection string using simple string checks (no regex)
validate_connection_string() {
    local conn_str="$1"
    if [[ "$conn_str" != *"HostName="* ]] || [[ "$conn_str" != *"DeviceId="* ]] || [[ "$conn_str" != *"SharedAccessKey="* ]]; then
        return 1
    fi
    return 0
}

# Extract device info from connection string using cut instead of regex
get_connection_string_value() {
    local conn_str="$1"
    local key="$2"
    echo "$conn_str" | tr ';' '\n' | grep "^$key=" | cut -d'=' -f2
}

# Set device info based on provisioning method
if [ "$PROVISIONING_METHOD" = "connection-string" ]; then
  if ! validate_connection_string "$CONNECTION_STRING"; then
      print_error "Invalid connection string format. It should include HostName, DeviceId, and SharedAccessKey."
      exit 1
  fi
  DEVICE_ID=$(get_connection_string_value "$CONNECTION_STRING" "DeviceId")
  HOSTNAME=$(get_connection_string_value "$CONNECTION_STRING" "HostName")
else # x509
  HOSTNAME=$IOTHUB_HOSTNAME
fi


# Installation status tracking
declare -A STATUS_TRACKER
STATUS_TRACKER["cleanup"]="Not Started"
STATUS_TRACKER["prerequisites"]="Not Started"
STATUS_TRACKER["microsoft_repo"]="Not Started"
STATUS_TRACKER["container_engine"]="Not Started"
STATUS_TRACKER["iotedge_runtime"]="Not Started"
STATUS_TRACKER["certs_generate"]="Not Started"
STATUS_TRACKER["certs_install"]="Not Started"
STATUS_TRACKER["iotedge_config"]="Not Started"
STATUS_TRACKER["iotedge_service"]="Not Started"
STATUS_TRACKER["edge_agent"]="Not Started"
STATUS_TRACKER["edge_hub"]="Not Started"
STATUS_TRACKER["connectivity"]="Not Started"

update_status() {
    local component="$1"
    local status="$2"
    
    if [[ -v STATUS_TRACKER[$component] ]]; then
        STATUS_TRACKER[$component]="$status"
    fi
}

# IMPORTANT: Define print_installation_summary function BEFORE it's called
print_installation_summary() {
    print_header "======================================================"
    print_header "IoT Edge Installation Summary"
    print_header "======================================================"
    
    format_status() {
        case "$1" in
            "Success"*) echo -e "${GREEN}$1${NC}" ;;
            "Already"*) echo -e "${BLUE}$1${NC}" ;;
            "Warning"*) echo -e "${YELLOW}$1${NC}" ;;
            "Failed"*) echo -e "${RED}$1${NC}" ;;
            "Not Running"*) echo -e "${YELLOW}$1${NC}" ;;
            "Not Started"*) echo -e "${RED}$1${NC}" ;;
            "In Progress"*) echo -e "${YELLOW}$1${NC}" ;;
            "Skipped"*) echo -e "${BLUE}$1${NC}" ;;
            *) echo -e "$1" ;;
        esac
    }
    
    [[ "$CLEAN_INSTALL" = true ]] && echo -e "IoT Edge Cleanup: $(format_status "${STATUS_TRACKER["cleanup"]}")"
    echo -e "Prerequisites Installation: $(format_status "${STATUS_TRACKER["prerequisites"]}")"
    echo -e "Microsoft Repository Setup: $(format_status "${STATUS_TRACKER["microsoft_repo"]}")"
    echo -e "Container Engine Installation: $(format_status "${STATUS_TRACKER["container_engine"]}")"
    echo -e "IoT Edge Runtime Installation: $(format_status "${STATUS_TRACKER["iotedge_runtime"]}")"
    if [ "$PROVISIONING_METHOD" = "x509" ]; then
      echo -e "Certificate Generation: $(format_status "${STATUS_TRACKER["certs_generate"]}")"
      echo -e "Certificate Installation: $(format_status "${STATUS_TRACKER["certs_install"]}")"
    fi
    echo -e "IoT Edge Configuration: $(format_status "${STATUS_TRACKER["iotedge_config"]}")"
    echo -e "IoT Edge Service: $(format_status "${STATUS_TRACKER["iotedge_service"]}")"
    echo -e "Edge Agent Module: $(format_status "${STATUS_TRACKER["edge_agent"]}")"
    echo -e "Edge Hub Module: $(format_status "${STATUS_TRACKER["edge_hub"]}")"
    echo -e "IoT Hub Connectivity: $(format_status "${STATUS_TRACKER["connectivity"]}")"
    
    print_header "======================================================"
    
    local failures=0
    local warnings=0
    for key in "${!STATUS_TRACKER[@]}"; do
        if [[ "${STATUS_TRACKER[$key]}" == Failed* ]]; then failures=$((failures + 1)); fi
        if [[ "${STATUS_TRACKER[$key]}" == Warning* || "${STATUS_TRACKER[$key]}" == "Not Running" ]]; then warnings=$((warnings + 1)); fi
    done
    
    if [ $failures -gt 0 ]; then
        echo -e "${RED}Installation completed with $failures failures.${NC}"
        echo -e "${RED}Please check the log file at $LOG_FILE for details.${NC}"
    elif [ $warnings -gt 0 ]; then
        echo -e "${YELLOW}Installation completed with $warnings warnings.${NC}"
        echo -e "${YELLOW}Some components may require attention.${NC}"
    else
        echo -e "${GREEN}Installation completed successfully.${NC}"
    fi

    if [ "$PROVISIONING_METHOD" = "x509" ] && [ $failures -eq 0 ]; then
        print_header "======================================================"
        print_header "ACTION REQUIRED: Register Device in Azure IoT Hub"
        print_header "======================================================"
        echo -e "1. Go to your IoT Hub in the Azure Portal."
        echo -e "2. Navigate to 'Devices' and click 'Add Device'."
        echo -e "3. Device ID: ${BLUE}$DEVICE_ID${NC}"
        echo -e "4. Authentication type: ${BLUE}X.509 Self-Signed${NC}."
        echo -e "5. Paste the following Primary Thumbprint:"
        THUMBPRINT=$(openssl x509 -in /var/aziot/certs/device-id.pem -noout -fingerprint -sha1 | sed 's/.*=//;s/://g' | tr 'a-f' 'A-F')
        echo -e "${YELLOW}$THUMBPRINT${NC}"
        echo -e "6. Click 'Save'."
        echo -e "After registration, modules should start deploying within a few minutes."
        print_header "======================================================"
    else
        print_header "======================================================"
        print_header "Next Steps:"
        print_header "1. Return to the deployment portal"
        print_header "2. Deploy your desired modules to this device"
        print_header "======================================================"
    fi

    print_header "Device Information:"
    echo -e "Device ID: ${BLUE}$DEVICE_ID${NC}"
    echo -e "IoT Hub: ${BLUE}$HOSTNAME${NC}"
    echo -e "OS: ${BLUE}$OS $VERSION_ID${NC}"
    echo -e "Hostname: ${BLUE}$(hostname)${NC}"
    echo -e "IP Address: ${BLUE}$(hostname -I | awk '{print $1}')${NC}"
    print_header "======================================================"
}

# Function to check command status with retry option
check_command() {
    local cmd="$1"
    local error_msg="$2"
    local component="$3"
    local max_retries="${4:-1}"
    local retry_interval="${5:-5}"
    local retries=0
    
    [ -n "$component" ] && update_status "$component" "In Progress"
    
    while [ $retries -lt $max_retries ]; do
        output=$(eval "$cmd" 2>&1)
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            [ $retries -gt 0 ] && print_status "Command succeeded on retry $retries"
            [ -n "$component" ] && update_status "$component" "Success"
            return 0
        else
            retries=$((retries + 1))
            if [ $retries -lt $max_retries ]; then
                print_warning "Command failed (attempt $retries/$max_retries). Retrying in ${retry_interval}s..."
                print_warning "Error: $output"
                sleep $retry_interval
            else
                print_error "$error_msg"
                print_error "Command output: $output"
                [ -n "$component" ] && update_status "$component" "Failed"
                report_status "ERROR" "$error_msg"
                return 1
            fi
        fi
    done
}

# Report setup status back to the deployment portal
report_status() {
    local status="$1"
    local message="$2"
    if [ -z "${CALLBACK_URL}" ]; then return; fi
    
    print_status "Reporting status: $status - $message"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    for i in {1..3}; do
        curl -s -m 10 -X POST "${CALLBACK_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"deviceId\":\"${DEVICE_ID}\",\"status\":\"${status}\",\"message\":\"${message}\",\"timestamp\":\"${timestamp}\"}" && break
        if [ $i -lt 3 ]; then
            print_warning "Failed to report status (attempt $i/3), retrying..."
            sleep 2
        else
            print_warning "Failed to report status after 3 attempts, continuing anyway"
        fi
    done
}

is_package_installed() {
    if [ -f /etc/redhat-release ]; then
        rpm -q "$1" >/dev/null 2>&1
    else
        dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
    fi
    return $?
}

# Function to perform a full cleanup of IoT Edge
clean_iotedge() {
    print_header "Starting complete cleanup of IoT Edge"
    update_status "cleanup" "In Progress"
    
    print_status "Stopping IoT Edge services..."
    systemctl stop aziot-edged aziot-identityd aziot-keyd aziot-certd aziot-tpmd &>/dev/null || true

    print_status "Removing IoT Edge packages..."
    if [ -f /etc/redhat-release ]; then
        yum remove --purge -y aziot-edge aziot-identity-service &>/dev/null || true
    else
        apt-get remove --purge -y aziot-edge aziot-identity-service &>/dev/null || true
    fi

    print_status "Cleaning up Docker environment..."
    if command -v docker &>/dev/null; then
        docker rm -f $(docker ps -aq) &>/dev/null || true
        docker system prune -af &>/dev/null || true
    fi

    print_status "Removing IoT Edge directories and certificates..."
    rm -rf /var/lib/aziot /opt/iotedge /etc/aziot /var/aziot ~/certificates ~/certs
    rm -f /usr/local/share/ca-certificates/azure-iot-test-only.root.ca.cert.pem.crt
    if command -v update-ca-certificates &>/dev/null; then
        update-ca-certificates --fresh &>/dev/null
    fi
    
    print_status "Cleanup complete."
    update_status "cleanup" "Success"
}

# Function to generate X.509 test certificates
generate_x509_certs() {
    print_header "Generating X.509 Test Certificates"
    
    print_status "Preparing certificate generation scripts..."
    CERT_DIR=~/certificates
    mkdir -p "$CERT_DIR"
    cd "$CERT_DIR"
    
    check_command "curl -L https://raw.githubusercontent.com/Azure/iotedge/main/tools/CACertificates/certGen.sh -o certGen.sh" "Failed to download certGen.sh" "certs_generate" 3 5 || return 1
    check_command "curl -L https://raw.githubusercontent.com/Azure/iotedge/main/tools/CACertificates/openssl_root_ca.cnf -o openssl_root_ca.cnf" "Failed to download openssl_root_ca.cnf" "certs_generate" 3 5 || return 1
    check_command "curl -L https://raw.githubusercontent.com/Azure/iotedge/main/tools/CACertificates/openssl_device_intermediate_ca.cnf -o openssl_device_intermediate_ca.cnf" "Failed to download openssl_device_intermediate_ca.cnf" "certs_generate" 3 5 || return 1
    chmod +x certGen.sh

    print_status "Creating root and intermediate CA..."
    check_command "./certGen.sh create_root_and_intermediate" "Failed to create root CA" "certs_generate" || return 1
    
    print_status "Generating device identity certificate for '$DEVICE_ID'..."
    check_command "./certGen.sh create_device_certificate \"$DEVICE_ID\"" "Failed to create device certificate" "certs_generate" || return 1
    
    print_status "Generating Edge CA certificate for '$EDGE_CA_NAME'..."
    check_command "./certGen.sh create_edge_device_ca_certificate \"$EDGE_CA_NAME\"" "Failed to create Edge CA certificate" "certs_generate" || return 1
    
    cd ~
    print_status "Certificate generation successful."
    update_status "certs_generate" "Success"
    return 0
}

# Function to install X.509 certificates and set permissions
install_x509_certs() {
    print_header "Installing X.509 Certificates"
    CERT_DIR=~/certificates

    print_status "Copying certificates to IoT Edge directories..."
    mkdir -p /var/aziot/certs /var/aziot/secrets
    check_command "cp $CERT_DIR/certs/azure-iot-test-only.root.ca.cert.pem /var/aziot/certs/" "Failed to copy root CA cert" "certs_install" || return 1
    check_command "cp $CERT_DIR/certs/iot-device-${DEVICE_ID}-full-chain.cert.pem /var/aziot/certs/device-id.pem" "Failed to copy device cert" "certs_install" || return 1
    check_command "cp $CERT_DIR/private/iot-device-${DEVICE_ID}.key.pem /var/aziot/secrets/device-id.key.pem" "Failed to copy device key" "certs_install" || return 1
    check_command "cp $CERT_DIR/certs/iot-edge-device-ca-${EDGE_CA_NAME}-full-chain.cert.pem /var/aziot/certs/edge-ca.pem" "Failed to copy Edge CA cert" "certs_install" || return 1
    check_command "cp $CERT_DIR/private/iot-edge-device-ca-${EDGE_CA_NAME}.key.pem /var/aziot/secrets/edge-ca.key.pem" "Failed to copy Edge CA key" "certs_install" || return 1

    print_status "Setting ownership and permissions..."
    chown aziotcs:aziotcs /var/aziot/certs && chmod 755 /var/aziot/certs
    chown aziotcs:aziotcs /var/aziot/certs/*.pem && chmod 644 /var/aziot/certs/*.pem
    chown aziotks:aziotks /var/aziot/secrets && chmod 700 /var/aziot/secrets
    chown aziotks:aziotks /var/aziot/secrets/*.pem && chmod 600 /var/aziot/secrets/*.pem
    
    print_status "Verifying permissions..."
    ls -la /var/aziot/certs/
    ls -la /var/aziot/secrets/
    
    update_status "certs_install" "Success"
    return 0
}

# Function to configure IoT Edge for X.509 provisioning
configure_iotedge_x509() {
    print_header "Configuring IoT Edge for X.509 Provisioning"
    
    if [ ! -f /etc/aziot/config.toml ]; then
        print_status "Creating config.toml from template..."
        check_command "cp /etc/aziot/config.toml.edge.template /etc/aziot/config.toml" "Failed to create config file" "iotedge_config" || return 1
    fi
    
    print_status "Updating config.toml for X.509 manual provisioning..."
    
    # Using a here-document to overwrite the config file with the correct TOML structure
    cat > /etc/aziot/config.toml <<EOF
# ==============================================================================
# Azure IoT Edge configuration
#
# Manual provisioning with X.509 certificate
# ==============================================================================

# Trust bundle cert
trust_bundle_cert = "file:///var/aziot/certs/azure-iot-test-only.root.ca.cert.pem"
 
[provisioning]
source = "manual"
iothub_hostname = "$IOTHUB_HOSTNAME"
device_id = "$DEVICE_ID"
 
[provisioning.authentication]
method = "x509"
 
# identity certificate private key
identity_pk = "file:///var/aziot/secrets/device-id.key.pem"
 
# identity certificate
identity_cert = "file:///var/aziot/certs/device-id.pem"
 
# Edge CA certificate
[edge_ca]
cert = "file:///var/aziot/certs/edge-ca.pem"
pk = "file:///var/aziot/secrets/edge-ca.key.pem"
 
[agent]
name = "edgeAgent"
type = "docker"
 
[agent.config]
image = "mcr.microsoft.com/azureiotedge-agent:1.5"
createOptions = { HostConfig = { Binds = ["/opt/iotedge/storage:/iotedge/storage"], Privileged = false, NetworkMode = "azure-iot-edge" } }
 
[agent.env]
"storageFolder" = "/iotedge/storage"

# Image garbage collection settings
[image_garbage_collection]
enabled = true
cleanup_recurrence = "1d"
image_age_cleanup_threshold = "2d" 
cleanup_time = "00:00"

EOF

    if [ $? -eq 0 ]; then
        print_status "config.toml updated successfully."
        update_status "iotedge_config" "Success"
        return 0
    else
        print_error "Failed to write to /etc/aziot/config.toml"
        update_status "iotedge_config" "Failed"
        return 1
    fi
}


print_header "======================================================"
print_header "IoT Edge Automated Setup Script"
print_header "Provisioning Method: $PROVISIONING_METHOD"
print_header "Device ID: $DEVICE_ID"
print_header "IoT Hub: $HOSTNAME" 
print_header "======================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Create a log file
LOG_FILE="/var/log/iotedge-setup.log"
exec > >(tee -a $LOG_FILE) 2>&1
print_status "Logging to $LOG_FILE"

# Perform cleanup if requested
if [ "$CLEAN_INSTALL" = true ]; then
    clean_iotedge
fi

# Detect OS distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VERSION=$VERSION_ID
    print_status "Detected OS: $OS $VERSION"
else
    print_error "Cannot detect OS distribution"
    report_status "ERROR" "Cannot detect OS distribution"
    exit 1
fi

# --- Main Installation Logic ---

# Handle OS-specific installation
if [ -f /etc/redhat-release ] || [[ "$OS" == *"Red Hat"* ]]; then
    # RHEL specific installation
    print_status "Detected Red Hat based system"
    update_status "prerequisites" "In Progress (RHEL)"
    check_command "yum install -y curl gnupg2 ca-certificates" "Failed to install prerequisites" "prerequisites" 3 5
    
    print_status "Adding Microsoft package repository for RHEL..."
    repo_url="https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm" # Default to 8
    if [[ "$VERSION_ID" == 9* ]]; then
        repo_url="https://packages.microsoft.com/config/rhel/9.0/packages-microsoft-prod.rpm"
    fi
    check_command "wget $repo_url -O packages-microsoft-prod.rpm" "Failed to download Microsoft repo" "microsoft_repo" 3 5
    check_command "yum localinstall -y packages-microsoft-prod.rpm" "Failed to install Microsoft repo" "microsoft_repo" 3 5
    rm packages-microsoft-prod.rpm
    
    report_status "INSTALLING" "Installing container engine (Moby)"
    print_status "Installing container engine..."
    if ! is_package_installed "moby-engine"; then
        check_command "yum install -y moby-engine moby-cli" "Failed to install container engine" "container_engine" 3 10
    else
        print_status "Moby container engine is already installed"
        update_status "container_engine" "Already Installed"
    fi
else
    # Ubuntu/Debian specific installation
    apt-get update || check_command "apt-get update" "Failed to update package repositories" "prerequisites" 3 5
    
    if ! is_package_installed "curl" || ! is_package_installed "gnupg2" || ! is_package_installed "apt-transport-https"; then
        print_status "Installing prerequisites..."
        check_command "apt-get install -y curl gnupg2 apt-transport-https ca-certificates" "Failed to install prerequisites" "prerequisites" 3 5
    else
        print_status "Prerequisites already installed"
        update_status "prerequisites" "Success"
    fi
    
    print_status "Adding Microsoft package repository..."
    repo_url=""
    case "$ID" in
        ubuntu)
            case "$VERSION_ID" in
                "20.04"|"22.04"|"24.04") repo_url="https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb" ;;
                *) print_warning "Unsupported Ubuntu version: $VERSION_ID. Using 22.04 repo."; repo_url="https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb" ;;
            esac
            ;;
        debian)
            case "$VERSION_ID" in
                "10"|"11"|"12") repo_url="https://packages.microsoft.com/config/debian/$VERSION_ID/packages-microsoft-prod.deb" ;;
                *) print_warning "Unsupported Debian version: $VERSION_ID. Using 11 repo."; repo_url="https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb" ;;
            esac
            ;;
        *)
            print_error "Unsupported OS: $OS. This script supports Debian, Ubuntu, and RHEL."
            report_status "ERROR" "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    check_command "curl $repo_url -o packages-microsoft-prod.deb" "Failed to download Microsoft repo" "microsoft_repo" 3 5
    check_command "dpkg -i packages-microsoft-prod.deb" "Failed to install Microsoft repo" "microsoft_repo" 3 5
    rm packages-microsoft-prod.deb
    
    report_status "INSTALLING" "Installing container engine (Moby)"
    print_status "Installing container engine..."
    if ! is_package_installed "moby-engine"; then
        apt-get update
        check_command "apt-get install -y moby-engine" "Failed to install container engine" "container_engine" 3 10
    else
        print_status "Moby container engine is already installed"
        update_status "container_engine" "Already Installed"
    fi
fi

# --- Common Installation Steps for all OS ---

# Configure container log size limits
print_status "Configuring container engine logging..."
mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ] || ! grep -q "log-driver" /etc/docker/daemon.json; then
    cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "local",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "live-restore": true
}
EOF
else
    print_status "Log configuration already exists, skipping modification"
fi

# Restart and enable Docker
print_status "Restarting and enabling container engine..."
check_command "systemctl restart docker" "Failed to restart container engine" "container_engine" 3 5
check_command "systemctl enable docker" "Failed to enable container engine" "container_engine" 3 5

# Install IoT Edge runtime
report_status "INSTALLING" "Installing IoT Edge runtime"
print_status "Installing Azure IoT Edge runtime..."
if ! is_package_installed "aziot-edge"; then
    if [ -f /etc/redhat-release ]; then
        check_command "yum install -y aziot-edge" "Failed to install IoT Edge runtime" "iotedge_runtime" 3 10
    else
        apt-get update
        check_command "apt-get install -y aziot-edge" "Failed to install IoT Edge runtime" "iotedge_runtime" 3 10
    fi
else
    print_status "Azure IoT Edge runtime is already installed"
    update_status "iotedge_runtime" "Already Installed"
fi

print_status "Creating AlignAV directory..."
mkdir -p /home/alignav && chown -R 1000:1000 /home/alignav && chmod -R 755 /home/alignav

# --- Configuration based on Provisioning Method ---

if [ "$PROVISIONING_METHOD" = "x509" ]; then
    report_status "CONFIGURING" "Generating X.509 certificates"
    generate_x509_certs || { print_installation_summary; exit 1; }
    
    report_status "CONFIGURING" "Installing X.509 certificates"
    install_x509_certs || { print_installation_summary; exit 1; }
    
    report_status "CONFIGURING" "Configuring IoT Edge for X.509"
    configure_iotedge_x509 || { print_installation_summary; exit 1; }
else # connection-string
    report_status "CONFIGURING" "Configuring IoT Edge with connection string"
    print_status "Configuring IoT Edge..."
    check_command "iotedge config mp --force --connection-string '$CONNECTION_STRING'" "Failed to configure IoT Edge" "iotedge_config" 3 5
    
    print_status "Configuring image garbage collection..."
    cat >> /etc/aziot/config.toml <<EOF

# Image garbage collection settings
[image_garbage_collection]
enabled = true
cleanup_recurrence = "1d"
image_age_cleanup_threshold = "2d" 
cleanup_time = "00:00"
EOF
fi

# Apply configuration
report_status "CONFIGURING" "Applying IoT Edge configuration"
print_status "Applying IoT Edge configuration..."
check_command "iotedge config apply -c /etc/aziot/config.toml" "Failed to apply IoT Edge configuration" "iotedge_config" 3 10 || { print_installation_summary; exit 1; }

# --- Verification ---

report_status "VERIFYING" "Verifying IoT Edge installation"
print_status "Waiting for IoT Edge to initialize..."
sleep 10

if systemctl is-active aziot-edged >/dev/null 2>&1; then
    print_status "IoT Edge service is running"
    update_status "iotedge_service" "Success"
else
    print_warning "IoT Edge service not active, attempting restart..."
    check_command "systemctl restart aziot-edged" "Failed to restart IoT Edge service" "iotedge_service" 2 5
    if systemctl is-active aziot-edged >/dev/null 2>&1; then
        print_status "IoT Edge service is now running after restart"
        update_status "iotedge_service" "Success (After Restart)"
    else
        print_error "IoT Edge service failed to start"
        update_status "iotedge_service" "Failed"
        report_status "ERROR" "IoT Edge service failed to start"
        print_installation_summary
        exit 1
    fi
fi

print_status "Waiting for modules to start (this may take a few minutes)..."
for i in {1..12}; do echo -n "."; sleep 5; done; echo ""

print_status "Running IoT Edge diagnostics check..."
if iotedge check; then
    print_status "IoT Edge check passed"
    update_status "connectivity" "Success"
else
    print_warning "IoT Edge check reported issues. This can be normal on a fresh install before modules are deployed from the cloud."
    update_status "connectivity" "Warning"
fi

print_status "Checking for running modules..."
if iotedge list | grep -q "edgeAgent.*running"; then
    print_status "IoT Edge Agent is running."
    update_status "edge_agent" "Success"
else
    print_warning "Edge Agent is not running yet. This may take a few more minutes."
    update_status "edge_agent" "Not Running"
fi
if iotedge list | grep -q "edgeHub.*running"; then
    print_status "IoT Edge Hub is running."
    update_status "edge_hub" "Success"
else
    print_warning "Edge Hub is not running yet. It must be deployed via IoT Hub."
    update_status "edge_hub" "Not Running"
fi

print_installation_summary

if [ "$PROVISIONING_METHOD" = "connection-string" ]; then
    report_status "READY" "IoT Edge setup completed successfully"
else
    report_status "ACTION_REQUIRED" "IoT Edge setup complete, manual device registration required in Azure."
fi

exit 0