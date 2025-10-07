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

# Parse command arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --connection-string)
      CONNECTION_STRING="$2"
      shift 2
      ;;
    --callback-url)
      CALLBACK_URL="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 --connection-string \"HostName=...\" [--callback-url \"https://...\"]"
      exit 0
      ;;
    *)
      echo "Unknown parameter: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# If no connection string is provided, prompt the user for one
if [ -z "$CONNECTION_STRING" ]; then
  echo -e "${YELLOW}No connection string provided.${NC}"
  echo -e "Please enter your IoT Edge device connection string:"
  read -p "> " CONNECTION_STRING
  
  # Check if the user provided a connection string
  if [ -z "$CONNECTION_STRING" ]; then
    echo -e "${RED}Error: Connection string is required to set up IoT Edge.${NC}"
    echo -e "You can get the connection string from Azure Portal > IoT Hub > IoT Edge > Your device > Connection string"
    exit 1
  fi
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
    
    # Check for required components
    if [[ "$conn_str" != *"HostName="* ]]; then
        return 1
    fi
    
    if [[ "$conn_str" != *"DeviceId="* ]]; then
        return 1
    fi
    
    if [[ "$conn_str" != *"SharedAccessKey="* ]]; then
        return 1
    fi
    
    return 0
}

# Validate the connection string
if ! validate_connection_string "$CONNECTION_STRING"; then
    print_error "Invalid connection string format. It should include HostName, DeviceId, and SharedAccessKey."
    exit 1
fi

# Extract device info from connection string using cut instead of regex
get_connection_string_value() {
    local conn_str="$1"
    local key="$2"
    
    # Extract the portion after the key
    local value=$(echo "$conn_str" | tr ';' '\n' | grep "^$key=" | cut -d'=' -f2)
    echo "$value"
}

# Extract device info
DEVICE_ID=$(get_connection_string_value "$CONNECTION_STRING" "DeviceId")
HOSTNAME=$(get_connection_string_value "$CONNECTION_STRING" "HostName")

# Installation status tracking
declare -A STATUS_TRACKER
STATUS_TRACKER["prerequisites"]="Not Started"
STATUS_TRACKER["microsoft_repo"]="Not Started"
STATUS_TRACKER["container_engine"]="Not Started"
STATUS_TRACKER["iotedge_runtime"]="Not Started"
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
    
    # Format status with colors
    format_status() {
        local status="$1"
        case "$status" in
            "Success"*)
                echo -e "${GREEN}$status${NC}"
                ;;
            "Already"*)
                echo -e "${BLUE}$status${NC}"
                ;;
            "Warning"*)
                echo -e "${YELLOW}$status${NC}"
                ;;
            "Failed"*)
                echo -e "${RED}$status${NC}"
                ;;
            "Not Running"*)
                echo -e "${YELLOW}$status${NC}"
                ;;
            "Not Started"*)
                echo -e "${RED}$status${NC}"
                ;;
            "In Progress"*)
                echo -e "${YELLOW}$status${NC}"
                ;;
            *)
                echo -e "$status"
                ;;
        esac
    }
    
    echo -e "Prerequisites Installation: $(format_status "${STATUS_TRACKER["prerequisites"]}")"
    echo -e "Microsoft Repository Setup: $(format_status "${STATUS_TRACKER["microsoft_repo"]}")"
    echo -e "Container Engine Installation: $(format_status "${STATUS_TRACKER["container_engine"]}")"
    echo -e "IoT Edge Runtime Installation: $(format_status "${STATUS_TRACKER["iotedge_runtime"]}")"
    echo -e "IoT Edge Configuration: $(format_status "${STATUS_TRACKER["iotedge_config"]}")"
    echo -e "IoT Edge Service: $(format_status "${STATUS_TRACKER["iotedge_service"]}")"
    echo -e "Edge Agent Module: $(format_status "${STATUS_TRACKER["edge_agent"]}")"
    echo -e "Edge Hub Module: $(format_status "${STATUS_TRACKER["edge_hub"]}")"
    echo -e "IoT Hub Connectivity: $(format_status "${STATUS_TRACKER["connectivity"]}")"
    
    print_header "======================================================"
    
    # Calculate overall success
    local failures=0
    local warnings=0
    
    for key in "${!STATUS_TRACKER[@]}"; do
        if [[ "${STATUS_TRACKER[$key]}" == Failed* ]]; then
            failures=$((failures + 1))
        elif [[ "${STATUS_TRACKER[$key]}" == Warning* || "${STATUS_TRACKER[$key]}" == "Not Running" ]]; then
            warnings=$((warnings + 1))
        fi
    done
    
    if [ $failures -gt 0 ]; then
        echo -e "${RED}Installation completed with $failures failures.${NC}"
        echo -e "${RED}Please check the log file at $LOG_FILE for details.${NC}"
        echo -e "${RED}You may need to correct these issues before deploying modules.${NC}"
    elif [ $warnings -gt 0 ]; then
        echo -e "${YELLOW}Installation completed with $warnings warnings.${NC}"
        echo -e "${YELLOW}Some components may require attention, but you can proceed with deployment.${NC}"
    else
        echo -e "${GREEN}Installation completed successfully with no issues.${NC}"
        echo -e "${GREEN}You can now proceed to deploy your monitoring modules.${NC}"
    fi
    
    print_header "======================================================"
    print_header "Next Steps:"
    print_header "1. Return to the deployment portal"
    print_header "2. Select your desired monitoring modules"
    print_header "3. Provide any required credentials"
    print_header "4. Deploy modules to your IoT Edge device"
    print_header "======================================================"
    
    # Print device info for reference
    print_header "Device Information:"
    echo -e "Device ID: ${BLUE}$DEVICE_ID${NC}"
    echo -e "IoT Hub: ${BLUE}$HOSTNAME${NC}"
    echo -e "OS: ${BLUE}$OS $VERSION_ID${NC}"
    hostname_output=$(hostname)
    echo -e "Hostname: ${BLUE}$hostname_output${NC}"
    ip_output=$(hostname -I | awk '{print $1}')
    echo -e "IP Address: ${BLUE}$ip_output${NC}"
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
    
    if [ -z "$component" ]; then
        component="command"
    else
        update_status "$component" "In Progress"
    fi
    
    while [ $retries -lt $max_retries ]; do
        # Execute command and capture output
        output=$(eval $cmd 2>&1)
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            # If successful on retry, print success message
            if [ $retries -gt 0 ]; then
                print_status "Command succeeded on retry $retries"
            fi
            [ ! -z "$component" ] && update_status "$component" "Success"
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
                print_error "Command: $cmd"
                [ ! -z "$component" ] && update_status "$component" "Failed"
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
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Only attempt callback if CALLBACK_URL is provided
    if [ ! -z "${CALLBACK_URL}" ]; then
        print_status "Reporting status: $status - $message"
        
        # Using curl with retries to report status back to server
        for i in {1..3}; do
            curl -s -m 10 -X POST "${CALLBACK_URL}" \
                -H "Content-Type: application/json" \
                -d "{\"deviceId\":\"${DEVICE_ID}\",\"status\":\"${status}\",\"message\":\"${message}\",\"timestamp\":\"${timestamp}\"}" && break
            
            # If we reach here, curl failed
            if [ $i -lt 3 ]; then
                print_warning "Failed to report status (attempt $i/3), retrying..."
                sleep 2
            else
                print_warning "Failed to report status after 3 attempts, continuing anyway"
            fi
        done
    fi
}

# Function to check if a package is installed
is_package_installed() {
    if [ -f /etc/redhat-release ]; then
        # For RHEL systems
        rpm -q "$1" >/dev/null 2>&1
        return $?
    else
        # For Debian/Ubuntu systems
        dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
        return $?
    fi
}

# Function to check if IoT Edge is already installed and configured
check_iotedge_status() {
    # Check if IoT Edge package is installed
    if is_package_installed "aziot-edge"; then
        print_status "IoT Edge is already installed"
        update_status "iotedge_runtime" "Already Installed"
        
        # Check if the configuration file exists
        if [ -f /etc/aziot/config.toml ]; then
            print_status "IoT Edge is already configured"
            update_status "iotedge_config" "Already Configured"
            
            # Check if the service is running
            if systemctl is-active aziot-edged >/dev/null 2>&1; then
                print_status "IoT Edge service is already running"
                update_status "iotedge_service" "Already Running"
                return 0  # Already installed and running
            else
                print_warning "IoT Edge is installed but not running"
                update_status "iotedge_service" "Not Running"
                return 1  # Installed but not running
            fi
        else
            print_warning "IoT Edge is installed but not configured"
            update_status "iotedge_config" "Not Configured"
            return 2  # Installed but not configured
        fi
    else
        print_status "IoT Edge is not installed"
        return 3  # Not installed
    fi
}

print_header "======================================================"
print_header "IoT Edge Automated Setup Script"
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

# Check current IoT Edge status
iotedge_status=$(check_iotedge_status)
iotedge_status_code=$?

if [ $iotedge_status_code -eq 0 ]; then
    print_status "IoT Edge is already installed, configured, and running"
    
    # Automatically reconfigure with the new connection string
    print_status "Reconfiguring with the provided connection string..."
    
    # Force reconfiguration
    check_command "iotedge config mp --force --connection-string '$CONNECTION_STRING'" "Failed to reconfigure IoT Edge" "iotedge_config" 3 5
    
    # Configure image garbage collection
    print_status "Configuring image garbage collection..."
    
    # Create temporary file with garbage collection settings
    cat > /tmp/garbage_collection.toml <<EOF

# Image garbage collection settings
[image_garbage_collection]
enabled = true
cleanup_recurrence = "1d"
image_age_cleanup_threshold = "2d" 
cleanup_time = "00:00"
EOF
    
    # Append garbage collection settings to the config
    check_command "cat /tmp/garbage_collection.toml >> /etc/aziot/config.toml" "Failed to add garbage collection settings" "iotedge_config" 3 5
    rm /tmp/garbage_collection.toml
    
    # Apply configuration
    print_status "Applying IoT Edge configuration..."
    check_command "iotedge config apply" "Failed to apply IoT Edge configuration" "iotedge_config" 3 5
    
    # Verify connection with updated configuration
    print_status "Verifying IoT Edge installation..."
    if iotedge check; then
        update_status "connectivity" "Success"
    else
        update_status "connectivity" "Warning"
    fi
    
    # Check if edgeAgent is running
    if iotedge list | grep -q "edgeAgent.*running"; then
        update_status "edge_agent" "Success"
    else
        update_status "edge_agent" "Not Running"
    fi
    
    # Check if edgeHub is running
    if iotedge list | grep -q "edgeHub.*running"; then
        update_status "edge_hub" "Success"
    else
        update_status "edge_hub" "Not Running"
    fi
    
    report_status "READY" "IoT Edge reconfigured successfully"
    print_header "======================================================"
    print_header "IoT Edge has been reconfigured with the new connection string"
    print_header "======================================================"
    
    # Show installation summary
    print_installation_summary
    exit 0
fi

# Start installation process
report_status "INSTALLING" "Starting IoT Edge installation"
print_status "Installing dependencies..."

# Handle OS-specific installation
if [ -f /etc/redhat-release ] || [[ "$OS" == *"Red Hat"* ]]; then
    # RHEL specific installation
    print_status "Detected Red Hat based system, using RHEL installation method"
    update_status "prerequisites" "In Progress (RHEL)"
    
    # Install prerequisites
    check_command "yum install -y curl gnupg2 ca-certificates" "Failed to install prerequisites" "prerequisites" 3 5
    
    # Add Microsoft repository for RHEL
    print_status "Adding Microsoft package repository for RHEL..."
    if [[ "$VERSION_ID" == 9* ]]; then
        check_command "wget https://packages.microsoft.com/config/rhel/9.0/packages-microsoft-prod.rpm -O packages-microsoft-prod.rpm" "Failed to download Microsoft package repository" "microsoft_repo" 3 5
    else
        # Default to RHEL 8 for older versions
        check_command "wget https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm -O packages-microsoft-prod.rpm" "Failed to download Microsoft package repository" "microsoft_repo" 3 5
    fi
    
    # Install the repository package
    check_command "yum localinstall -y packages-microsoft-prod.rpm" "Failed to install Microsoft package repository" "microsoft_repo" 3 5
    rm packages-microsoft-prod.rpm
    
    # Install container runtime (Moby)
    report_status "INSTALLING" "Installing container engine (Moby)"
    print_status "Installing container engine for RHEL..."
    
    # Check if container engine is already installed
    if command -v docker >/dev/null 2>&1; then
        print_status "Docker container engine is already installed"
        update_status "container_engine" "Docker Already Installed"
    elif command -v moby-engine >/dev/null 2>&1 || is_package_installed "moby-engine"; then
        print_status "Moby container engine is already installed"
        update_status "container_engine" "Moby Already Installed"
    else
        # Install container runtime (Moby)
        check_command "yum install -y moby-engine moby-cli" "Failed to install container engine" "container_engine" 3 10
    fi
    
    # Configure container log size limits to avoid disk filling up
    print_status "Configuring container engine logging..."
    
    # Check if daemon.json already exists and contains log configuration
    if [ -f /etc/docker/daemon.json ]; then
        print_status "Container engine config file exists, checking configuration..."
        
        # Check if log configuration already exists
        if grep -q "log-driver" /etc/docker/daemon.json; then
            print_status "Log configuration already exists, skipping modification"
        else
            print_status "Adding log configuration to existing config file"
            # Create backup of original file
            cp /etc/docker/daemon.json /etc/docker/daemon.json.bak
            
            # Add log configuration to existing file (this is a simplistic approach, might need improvement)
            sed -i 's/{/{\n    "log-driver": "local",\n    "log-opts": {\n        "max-size": "10m",\n        "max-file": "3"\n    },/g' /etc/docker/daemon.json
        fi
    else
        # Create directory if it doesn't exist
        mkdir -p /etc/docker
        
        # Create new config file
        cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "local",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF
    fi
    
    # Restart Docker to apply logging configuration
    if systemctl is-active docker >/dev/null 2>&1; then
        print_status "Restarting container engine to apply configuration..."
        check_command "systemctl restart docker" "Failed to restart container engine" "container_engine" 3 5
    else
        print_status "Starting container engine..."
        check_command "systemctl start docker" "Failed to start container engine" "container_engine" 3 5
    fi
    
    # Enable Docker to start on boot
    check_command "systemctl enable docker" "Failed to enable container engine to start on boot" "container_engine" 3 5
    
    # Install IoT Edge runtime
    report_status "INSTALLING" "Installing IoT Edge runtime"
    print_status "Installing Azure IoT Edge runtime for RHEL..."
    check_command "yum install -y aziot-edge" "Failed to install Azure IoT Edge runtime" "iotedge_runtime" 3 10
    
else
    # Ubuntu/Debian specific installation
    # Update package repositories
    apt-get update || {
        print_warning "Failed to update package repositories, retrying with error handling"
        check_command "apt-get update" "Failed to update package repositories after retries" "prerequisites" 3 5
    }
    
    # Install curl and other prerequisites if not already installed
    if ! is_package_installed "curl" || ! is_package_installed "gnupg2" || ! is_package_installed "apt-transport-https"; then
        print_status "Installing prerequisites..."
        check_command "apt-get install -y curl gnupg2 apt-transport-https ca-certificates" "Failed to install prerequisites" "prerequisites" 3 5
    else
        print_status "Prerequisites already installed"
        update_status "prerequisites" "Success"
    fi
    
    print_status "Adding Microsoft package repository..."
    
    # Add Microsoft's package repository
    case "$OS" in
        "Ubuntu")
            case "$VERSION_ID" in
                "20.04")
                    curl https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    ;;
                "22.04")
                    curl https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    ;;
                "24.04")
                    curl https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    ;;
                *)
                    print_warning "Unsupported Ubuntu version: $VERSION_ID, trying to use closest version..."
                    if [[ "$VERSION_ID" > "24.04" ]]; then
                        curl https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    elif [[ "$VERSION_ID" > "22.04" ]]; then
                        curl https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    else
                        curl https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    fi
                    ;;
            esac
            ;;
        "Debian")
            case "$VERSION_ID" in
                "10")
                    curl https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    ;;
                "11")
                    curl https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    ;;
                "12")
                    curl https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    ;;
                *)
                    print_warning "Unsupported Debian version: $VERSION_ID, trying to use closest version..."
                    if [[ "$VERSION_ID" > "12" ]]; then
                        curl https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    elif [[ "$VERSION_ID" > "11" ]]; then
                        curl https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    else
                        curl https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -o packages-microsoft-prod.deb
                    fi
                    ;;
            esac
            ;;
        *)
            # Handle other distributions like CentOS, RHEL or unknown cases
            print_warning "OS $OS is not officially supported by this script"
            print_warning "Attempting to continue, but installation might fail"
            update_status "microsoft_repo" "Skipped (Unsupported OS)"
            
            # Try to determine if it's a Red Hat based system
            if [ -f /etc/redhat-release ]; then
                print_warning "Detected Red Hat based system, using manual installation method"
                
                # Install IoT Edge for RHEL/CentOS
                check_command "curl -L https://aka.ms/libiothsm-std-linux-armhf.tar.gz -o libiothsm-std.tar.gz && tar -xvf libiothsm-std.tar.gz && rm libiothsm-std.tar.gz" "Failed to download IoT Edge dependencies" "microsoft_repo" 3 5
                
                report_status "ERROR" "Unsupported OS: $OS. Please use Ubuntu or Debian"
                exit 1
            else
                report_status "ERROR" "Unsupported OS: $OS"
                exit 1
            fi
            ;;
    esac
    
    # If we get here, we have the .deb file for Microsoft's repo
    if [ -f packages-microsoft-prod.deb ]; then
        check_command "dpkg -i packages-microsoft-prod.deb" "Failed to install Microsoft package repository" "microsoft_repo" 3 5
        rm packages-microsoft-prod.deb
    else
        print_error "Failed to download Microsoft package repository"
        update_status "microsoft_repo" "Failed"
        report_status "ERROR" "Failed to download Microsoft package repository"
        exit 1
    fi
    
    report_status "INSTALLING" "Installing container engine (Moby)"
    print_status "Installing container engine..."
    
    # Check if container engine is already installed
    if command -v docker >/dev/null 2>&1; then
        print_status "Docker container engine is already installed"
        update_status "container_engine" "Docker Already Installed"
    elif command -v moby-engine >/dev/null 2>&1 || is_package_installed "moby-engine"; then
        print_status "Moby container engine is already installed"
        update_status "container_engine" "Moby Already Installed"
    else
        # Install container runtime (Moby)
        apt-get update
        check_command "apt-get install -y moby-engine" "Failed to install container engine" "container_engine" 3 10
    fi
    
    # Configure container log size limits to avoid disk filling up
    print_status "Configuring container engine logging..."
    
    # Check if daemon.json already exists and contains log configuration
    if [ -f /etc/docker/daemon.json ]; then
        print_status "Container engine config file exists, checking configuration..."
        
        # Check if log configuration already exists
        if grep -q "log-driver" /etc/docker/daemon.json; then
            print_status "Log configuration already exists, skipping modification"
        else
            print_status "Adding log configuration to existing config file"
            # Create backup of original file
            cp /etc/docker/daemon.json /etc/docker/daemon.json.bak
            
            # Add log configuration to existing file (this is a simplistic approach, might need improvement)
            sed -i 's/{/{\n    "log-driver": "local",\n    "log-opts": {\n        "max-size": "10m",\n        "max-file": "3"\n    },/g' /etc/docker/daemon.json
        fi
    else
        # Create directory if it doesn't exist
        mkdir -p /etc/docker
        
        # Create new config file
        cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "local",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF
    fi
    
    # Restart Docker to apply logging configuration
    if systemctl is-active docker >/dev/null 2>&1; then
        print_status "Restarting container engine to apply configuration..."
        check_command "systemctl restart docker" "Failed to restart container engine" "container_engine" 3 5
    else
        print_status "Starting container engine..."
        check_command "systemctl start docker" "Failed to start container engine" "container_engine" 3 5
    fi
    
    # Enable Docker to start on boot
    check_command "systemctl enable docker" "Failed to enable container engine to start on boot" "container_engine" 3 5
    
    print_status "Creating AlignAV directory..."
    mkdir -p /home/alignav
     
    # Set proper ownership and permissions
    chown -R 1000:1000 /home/alignav
    chmod -R 755 /home/alignav
    
    report_status "INSTALLING" "Installing IoT Edge runtime"
    print_status "Installing Azure IoT Edge runtime..."
    
    # Install IoT Edge runtime if not already installed
    if ! is_package_installed "aziot-edge"; then
        apt-get update
        check_command "apt-get install -y aziot-edge" "Failed to install Azure IoT Edge runtime" "iotedge_runtime" 3 10
    else
        print_status "Azure IoT Edge runtime is already installed"
        update_status "iotedge_runtime" "Already Installed"
    fi
fi

print_status "Creating AlignAV directory..."
mkdir -p /home/alignav
 
# Set proper ownership and permissions
chown -R 1000:1000 /home/alignav
chmod -R 755 /home/alignav

report_status "CONFIGURING" "Configuring IoT Edge"
print_status "Configuring IoT Edge with connection string..."

# Check if IoT Edge is already configured
if [ -f /etc/aziot/config.toml ]; then
    print_warning "IoT Edge configuration file already exists"
    print_status "Reconfiguring IoT Edge with new connection string..."
    
    # Force reconfiguration
    check_command "iotedge config mp --force --connection-string '$CONNECTION_STRING'" "Failed to reconfigure IoT Edge" "iotedge_config" 3 5
else
    # Create configuration
    check_command "iotedge config mp --connection-string '$CONNECTION_STRING'" "Failed to create IoT Edge configuration" "iotedge_config" 3 5
fi

# Add image garbage collection configuration
print_status "Configuring image garbage collection..."

# Create temporary file with garbage collection settings
cat > /tmp/garbage_collection.toml <<EOF

# Image garbage collection settings
[image_garbage_collection]
enabled = true
cleanup_recurrence = "1d"
image_age_cleanup_threshold = "2d" 
cleanup_time = "00:00"
EOF

# Append garbage collection settings to the config
check_command "cat /tmp/garbage_collection.toml >> /etc/aziot/config.toml" "Failed to add garbage collection settings" "iotedge_config" 3 5
rm /tmp/garbage_collection.toml

# Apply configuration
print_status "Applying IoT Edge configuration..."
check_command "iotedge config apply" "Failed to apply IoT Edge configuration" "iotedge_config" 3 5

report_status "VERIFYING" "Verifying IoT Edge installation"
print_status "Verifying installation..."

# Wait for edge daemon to initialize
print_status "Waiting for IoT Edge to initialize..."
sleep 10

# Check if IoT Edge system service is running
is_service_active=false
for i in {1..5}; do
    if systemctl is-active aziot-edged >/dev/null 2>&1; then
        is_service_active=true
        update_status "iotedge_service" "Success"
        break
    else
        print_warning "IoT Edge system service is not running yet, waiting... (attempt $i/5)"
        sleep 10
    fi
done

if [ "$is_service_active" = true ]; then
    print_status "IoT Edge system service is running"
else
    print_error "IoT Edge system service failed to start"
    update_status "iotedge_service" "Failed"
    systemctl status aziot-edged
    
    # Try to restart the service
    print_warning "Attempting to restart IoT Edge service..."
    check_command "systemctl restart aziot-edged" "Failed to restart IoT Edge service" "iotedge_service" 2 5
    
    # Check again if service is running
    if systemctl is-active aziot-edged >/dev/null 2>&1; then
        print_status "IoT Edge service is now running after restart"
        update_status "iotedge_service" "Success (After Restart)"
    else
        print_error "IoT Edge service failed to start even after restart"
        update_status "iotedge_service" "Failed"
        report_status "ERROR" "IoT Edge system service failed to start"
        print_installation_summary
        exit 1
    fi
fi

# Wait for edge daemon to initialize and connect
print_status "Waiting for IoT Edge to initialize and connect to IoT Hub..."
for i in {1..12}; do
    if [ $((i % 3)) -eq 0 ]; then
        echo ""
        print_status "Still waiting for IoT Edge to initialize (attempt $i/12)..."
    fi
    echo -n "."
    sleep 5
done
echo ""

# Verify configuration and connectivity
print_status "Running IoT Edge diagnostics check..."
if iotedge check; then
    update_status "connectivity" "Success"
else
    # Don't fail on check errors, as some warnings are normal on a fresh install
    check_exit_code=$?
    if [ $check_exit_code -ne 0 ]; then
        print_warning "IoT Edge check reported issues (code: $check_exit_code)"
        print_warning "Some warnings are normal for a new installation, continuing..."
        update_status "connectivity" "Warning"
        report_status "WARNING" "IoT Edge check reported minor issues"
    else
        print_status "IoT Edge check passed successfully"
        update_status "connectivity" "Success"
        report_status "CONNECTED" "IoT Edge successfully connected to IoT Hub"
    fi
fi

# Check if edgeAgent is running - this is a better indicator of success
print_status "Checking if IoT Edge Agent is running..."
edge_agent_running=false
for i in {1..5}; do
    if iotedge list | grep -q "edgeAgent.*running"; then
        edge_agent_running=true
        update_status "edge_agent" "Success"
        break
    else
        print_warning "Edge Agent not running yet, waiting... (attempt $i/5)"
        sleep 15
    fi
done

if [ "$edge_agent_running" = true ]; then
    print_status "IoT Edge Agent is running - installation successful!"
    report_status "READY" "IoT Edge setup completed successfully with Edge Agent running"
else
    print_warning "Edge Agent is not running yet, but IoT Edge service is active"
    update_status "edge_agent" "Not Running"
    print_warning "This might be normal for initial deployment, check the status later"
    report_status "WARNING" "IoT Edge setup completed but Edge Agent is not running yet"
fi

# Check if edgeHub is running
print_status "Checking if IoT Edge Hub is running..."
edge_hub_running=false
if iotedge list | grep -q "edgeHub.*running"; then
    edge_hub_running=true
    update_status "edge_hub" "Success"
    print_status "IoT Edge Hub is running"
else
    print_warning "Edge Hub is not running yet"
    update_status "edge_hub" "Not Running"
    print_warning "This is normal for initial deployment, as edgeHub must be deployed separately"
fi

print_installation_summary

# Create a status file to indicate successful installation
echo "$(date -u) - IoT Edge installation completed" > /var/lib/aziot/iotedge_setup_complete

report_status "READY" "IoT Edge setup completed successfully"
exit 0
