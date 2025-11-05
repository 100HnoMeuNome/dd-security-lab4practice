#!/bin/bash

# Datadog Runtime Security Rules Trigger Script
# This script simulates various security events to test Datadog CWP/Runtime Security detection
# Based on MITRE ATT&CK techniques

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_rule() {
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Wait function
wait_for_user() {
    if [ "$INTERACTIVE" = true ]; then
        read -p "Press Enter to continue..."
    else
        sleep 2
    fi
}

# Cleanup function
cleanup_resources() {
    print_info "Cleaning up resources..."
    kubectl delete deployment nginx-deployment 2>/dev/null || true
    kubectl delete pod busybox 2>/dev/null || true
    kubectl delete pod my-shell 2>/dev/null || true
    print_success "Cleanup completed"
}

# Rule 1: Launch Privileged Container
rule_01_privileged_container() {
    print_rule "Rule 1: (T1610) Launch Privileged Container"
    print_info "Creating privileged nginx deployment..."

    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 1
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        securityContext:
          privileged: true
EOF

    print_success "Privileged container created"
    sleep 5
    kubectl delete deployment nginx-deployment
    wait_for_user
}

# Rule 2: Launch Remote File Copy Tools in Container
rule_02_remote_file_copy() {
    print_rule "Rule 2: (T1105) Launch Remote File Copy Tools in Container"
    print_info "Installing and executing rsync in container..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq rsync && rsync --version"

    print_success "Remote file copy tool executed"
    wait_for_user
}

# Rule 3: Docker client executed in container
rule_03_docker_client() {
    print_rule "Rule 3: (T1609) Docker client executed in container"
    print_info "Installing and executing Docker client in container..."

    kubectl run my-shell --rm -i --privileged --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq curl && curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh && docker --version"

    print_success "Docker client executed"
    wait_for_user
}

# Rule 4: Escape attempt detected in privileged container
rule_04_escape_attempt() {
    print_rule "Rule 4: (T1611) Escape attempt detected in privileged container"
    print_info "Attempting container escape actions..."

    kubectl run my-shell --rm -i --privileged --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq e2fsprogs && echo 'q' | debugfs || true; mount | head -5"

    print_success "Escape attempt triggered"
    wait_for_user
}

# Rule 5: Schedule Cron Jobs
rule_05_cron_jobs() {
    print_rule "Rule 5: (T1053.003) Schedule Cron Jobs"
    print_info "Creating cron job file..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "touch /etc/cron.daily/testfile && ls -la /etc/cron.daily/testfile"

    print_success "Cron job scheduled"
    wait_for_user
}

# Rule 6: Dynamic linker changed
rule_06_dynamic_linker() {
    print_rule "Rule 6: (T1574.006) Dynamic linker changed"
    print_info "Modifying dynamic linker configuration..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "touch /etc/ld.so.preload && ls -la /etc/ld.so.preload"

    print_success "Dynamic linker changed"
    wait_for_user
}

# Rule 7: DB program spawned process
rule_07_db_spawn() {
    print_rule "Rule 7: (T1059) DB program spawned process"
    print_info "Simulating database program spawning process..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "cp /usr/bin/bash ./mysqld && chmod +x ./mysqld && ./mysqld -c 'echo Database simulation'"

    print_success "DB program spawn detected"
    wait_for_user
}

# Rule 8: Lateral Movement using SSH
rule_08_ssh_lateral() {
    print_rule "Rule 8: (T1021.004) Lateral Movement using SSH"
    print_warning "This rule requires an external SSH target - simulating SSH client usage"
    print_info "Installing and attempting SSH connection..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq openssh-client && ssh -V"

    print_success "SSH lateral movement simulated"
    wait_for_user
}

# Rule 9: Delete or rename shell history
rule_09_delete_history() {
    print_rule "Rule 9: (T1070) Delete or rename shell history"
    print_info "Deleting shell history..."

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: busybox
spec:
  containers:
  - image: busybox
    command:
      - /bin/sh
    args: ["-c", "touch /root/.bash_history; rm /root/.bash_history; sleep 5"]
    imagePullPolicy: IfNotPresent
    name: busybox
  restartPolicy: Never
EOF

    sleep 10
    kubectl delete pod busybox 2>/dev/null || true
    print_success "Shell history deleted"
    wait_for_user
}

# Rule 10: Specific discovery tool executed in container
rule_10_discovery_tool() {
    print_rule "Rule 10: (T1613) Specific discovery tool executed in container"
    print_info "Installing and executing masscan..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq masscan && masscan --version"

    print_success "Discovery tool executed"
    wait_for_user
}

# Rule 11: Amicontained download detected
rule_11_amicontained() {
    print_rule "Rule 11: (T1613) Amicontained download detected in container"
    print_info "Attempting to download amicontained..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq curl && curl -sL https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64 -o /tmp/amicontained || echo 'Download attempted'"

    print_success "Amicontained download triggered"
    wait_for_user
}

# Rule 12: Disable Security Tools
rule_12_disable_security() {
    print_rule "Rule 12: (T1562.001) Disable Security Tools"
    print_info "Attempting to stop security service..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq apparmor && service apparmor stop || echo 'Service stop attempted'"

    print_success "Security tool disable attempted"
    wait_for_user
}

# Rule 13: HugePages changed in container
rule_13_hugepages() {
    print_rule "Rule 13: (T1496) HugePages changed in container"
    print_info "Changing HugePages configuration..."

    kubectl run my-shell --rm -i --privileged --image ubuntu --restart=Never -- bash -c "sysctl vm.nr_hugepages || sysctl -w vm.nr_hugepages=2048 || echo 'HugePages change attempted'"

    print_success "HugePages modification triggered"
    wait_for_user
}

# Rule 14: Detect crypto miners using Stratum protocol
rule_14_crypto_miner() {
    print_rule "Rule 14: (T1496) Detect crypto miners using the Stratum protocol"
    print_info "Simulating Stratum protocol connection..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq curl && curl -X POST -m 5 stratum+tcp://pool.supportxmr.com:3333 || echo 'Stratum connection attempted'"

    print_success "Crypto miner activity simulated"
    wait_for_user
}

# Rule 15: Modify Shell Configuration File
rule_15_modify_shell() {
    print_rule "Rule 15: (T1546.004) Modify Shell Configuration File"
    print_info "Modifying shell configuration..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "touch /root/.bashrc && echo 'export TEST=1' >> /root/.bashrc && cat /root/.bashrc"

    print_success "Shell configuration modified"
    wait_for_user
}

# Rule 16: Update Package Repository
rule_16_update_repo() {
    print_rule "Rule 16: (T1059.004) Update Package Repository"
    print_info "Modifying package repository..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "touch /etc/apt/sources.list.d/testfile.list && ls -la /etc/apt/sources.list.d/"

    print_success "Package repository modified"
    wait_for_user
}

# Rule 17: Read ssh information
rule_17_read_ssh() {
    print_rule "Rule 17: (T1082) Read ssh information"
    print_info "Reading SSH configuration and keys..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "mkdir -p /root/.ssh && touch /root/.ssh/test_key && cat /root/.ssh/test_key"

    print_success "SSH information accessed"
    wait_for_user
}

# Rule 20: Terminal shell in container
rule_20_terminal_shell() {
    print_rule "Rule 20: (T1059.004) Terminal shell in container"
    print_info "Spawning interactive shell in container..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "echo 'Shell spawned successfully'"

    print_success "Terminal shell spawned"
    wait_for_user
}

# Rule 22: Contact EC2 Instance Metadata Service
rule_22_ec2_metadata() {
    print_rule "Rule 22: (T1613) Contact EC2 Instance Metadata Service From Container"
    print_info "Attempting to contact EC2 metadata service..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq curl && curl -m 5 http://169.254.169.254/latest/meta-data/ || echo 'EC2 metadata access attempted'"

    print_success "EC2 metadata access triggered"
    wait_for_user
}

# Rule 23: Contact K8S API Server
rule_23_k8s_api() {
    print_rule "Rule 23: (T1613) Contact K8S API Server From Container"
    print_info "Contacting Kubernetes API server..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq curl && curl -k https://kubernetes.default.svc.cluster.local || echo 'K8s API access attempted'"

    print_success "K8s API access triggered"
    wait_for_user
}

# Rule 24: Launch Package Management Process
rule_24_package_mgmt() {
    print_rule "Rule 24: (T1543) Launch Package Management Process in Container"
    print_info "Installing package using apt..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq nano && nano --version"

    print_success "Package management process executed"
    wait_for_user
}

# Rule 25: Netcat Remote Code Execution
rule_25_netcat_rce() {
    print_rule "Rule 25: (T1059.004) Netcat Remote Code Execution in Container"
    print_info "Installing and running netcat..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq netcat-traditional && echo 'Netcat installed' | nc -l -p 9999 & sleep 2 && killall nc"

    print_success "Netcat execution triggered"
    wait_for_user
}

# Rule 26: Clear Log Activities
rule_26_clear_logs() {
    print_rule "Rule 26: (T1070.002) Clear Log Activities"
    print_info "Writing to system logs..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "echo 'test' > /var/log/test.log 2>/dev/null || echo 'Log write attempted'"

    print_success "Log activity triggered"
    wait_for_user
}

# Rule 27: Create Symlink Over Sensitive Files
rule_27_symlink() {
    print_rule "Rule 27: (T1059.004) Create Symlink Over Sensitive Files"
    print_info "Creating symlink to sensitive location..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "ln -s /etc/shadow /tmp/shadow_link && ls -la /tmp/shadow_link"

    print_success "Symlink created"
    wait_for_user
}

# Rule 32: Detect miner termination
rule_32_miner_termination() {
    print_rule "Rule 32: (T1496) Detect miner termination in container"
    print_info "Simulating miner process termination..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "pkill -f xmrig || pkill -f minerd || echo 'Miner termination attempted'"

    print_success "Miner termination triggered"
    wait_for_user
}

# Rule 33: File attributes changed
rule_33_file_attrs() {
    print_rule "Rule 33: (T1222.002) File attributes changed in container"
    print_info "Changing file attributes..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq e2fsprogs && touch /tmp/test_file && chattr +i /tmp/test_file 2>/dev/null || echo 'File attribute change attempted'"

    print_success "File attributes modified"
    wait_for_user
}

# Rule 34: Set Setuid or Setgid bit
rule_34_setuid() {
    print_rule "Rule 34: (T1548.001) Set Setuid or Setgid bit"
    print_info "Setting SUID bit on file..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "touch /tmp/test_file && chmod u+s /tmp/test_file && ls -la /tmp/test_file"

    print_success "SUID bit set"
    wait_for_user
}

# Rule 35: Dangerous deletion
rule_35_dangerous_delete() {
    print_rule "Rule 35: (T1070.004) Dangerous deletion detected in container"
    print_info "Performing dangerous deletion..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "mkdir -p /tmp/testdir && touch /tmp/testdir/file && rm -rf /tmp/testdir"

    print_success "Dangerous deletion executed"
    wait_for_user
}

# Rule 36: Possible IRC communication
rule_36_irc() {
    print_rule "Rule 36: (T1071) Possible IRC communication in container"
    print_info "Simulating IRC connection..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "apt-get update -qq && apt-get install -y -qq netcat-traditional && echo 'IRC test' | nc -w 2 irc.freenode.net 6667 || echo 'IRC connection attempted'"

    print_success "IRC communication simulated"
    wait_for_user
}

# Rule 41: Search Private Keys or Passwords
rule_41_search_secrets() {
    print_rule "Rule 41: (T1552) Search Private Keys or Passwords"
    print_info "Searching for private keys..."

    kubectl run my-shell --rm -i --image ubuntu --restart=Never -- bash -c "find /root -name 'id_rsa' 2>/dev/null || find /home -name '*.pem' 2>/dev/null || echo 'Secret search performed'"

    print_success "Secret search executed"
    wait_for_user
}

# Main menu
show_menu() {
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║    Datadog Runtime Security Rules Trigger Script     ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"
    echo "Select an option:"
    echo "  1) Run ALL rules sequentially"
    echo "  2) Run QUICK test (subset of rules)"
    echo "  3) Run individual rule"
    echo "  4) Cleanup resources"
    echo "  5) Exit"
    echo ""
}

show_individual_menu() {
    echo -e "\n${YELLOW}Select individual rule:${NC}"
    echo "  1) T1610 - Privileged Container"
    echo "  2) T1105 - Remote File Copy Tools"
    echo "  3) T1609 - Docker Client in Container"
    echo "  4) T1611 - Container Escape Attempt"
    echo "  5) T1053.003 - Schedule Cron Jobs"
    echo "  6) T1574.006 - Dynamic Linker Changed"
    echo "  7) T1059 - DB Program Spawned Process"
    echo "  8) T1021.004 - SSH Lateral Movement"
    echo "  9) T1070 - Delete Shell History"
    echo " 10) T1613 - Discovery Tool Executed"
    echo " 11) T1613 - Amicontained Download"
    echo " 12) T1562.001 - Disable Security Tools"
    echo " 13) T1496 - HugePages Changed"
    echo " 14) T1496 - Crypto Miner Detection"
    echo " 15) T1546.004 - Modify Shell Config"
    echo " 16) T1059.004 - Update Package Repository"
    echo " 17) T1082 - Read SSH Information"
    echo " 20) T1059.004 - Terminal Shell"
    echo " 22) T1613 - EC2 Metadata Service"
    echo " 23) T1613 - K8S API Server Contact"
    echo " 24) T1543 - Package Management"
    echo " 25) T1059.004 - Netcat RCE"
    echo " 26) T1070.002 - Clear Logs"
    echo " 27) T1059.004 - Symlink Sensitive Files"
    echo " 32) T1496 - Miner Termination"
    echo " 33) T1222.002 - File Attributes Changed"
    echo " 34) T1548.001 - Set SUID/SGID"
    echo " 35) T1070.004 - Dangerous Deletion"
    echo " 36) T1071 - IRC Communication"
    echo " 41) T1552 - Search Secrets"
    echo "  0) Back to main menu"
    echo ""
}

run_all_rules() {
    print_info "Running ALL runtime security rules..."
    INTERACTIVE=false

    rule_01_privileged_container
    rule_02_remote_file_copy
    rule_03_docker_client
    rule_04_escape_attempt
    rule_05_cron_jobs
    rule_06_dynamic_linker
    rule_07_db_spawn
    rule_08_ssh_lateral
    rule_09_delete_history
    rule_10_discovery_tool
    rule_11_amicontained
    rule_12_disable_security
    rule_13_hugepages
    rule_14_crypto_miner
    rule_15_modify_shell
    rule_16_update_repo
    rule_17_read_ssh
    rule_20_terminal_shell
    rule_22_ec2_metadata
    rule_23_k8s_api
    rule_24_package_mgmt
    rule_25_netcat_rce
    rule_26_clear_logs
    rule_27_symlink
    rule_32_miner_termination
    rule_33_file_attrs
    rule_34_setuid
    rule_35_dangerous_delete
    rule_36_irc
    rule_41_search_secrets

    print_success "All rules executed!"
}

run_quick_test() {
    print_info "Running QUICK test (subset of common rules)..."
    INTERACTIVE=false

    rule_01_privileged_container
    rule_02_remote_file_copy
    rule_05_cron_jobs
    rule_09_delete_history
    rule_17_read_ssh
    rule_22_ec2_metadata
    rule_23_k8s_api
    rule_24_package_mgmt
    rule_34_setuid
    rule_41_search_secrets

    print_success "Quick test completed!"
}

# Main execution
INTERACTIVE=true

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl not found. Please install kubectl first."
    exit 1
fi

# Check if connected to a cluster
if ! kubectl cluster-info &> /dev/null; then
    print_error "Not connected to a Kubernetes cluster. Please configure kubectl."
    exit 1
fi

# Trap to cleanup on exit
trap cleanup_resources EXIT INT TERM

while true; do
    show_menu
    read -p "Enter your choice: " choice

    case $choice in
        1)
            run_all_rules
            ;;
        2)
            run_quick_test
            ;;
        3)
            while true; do
                show_individual_menu
                read -p "Enter rule number: " rule_choice

                case $rule_choice in
                    1) rule_01_privileged_container ;;
                    2) rule_02_remote_file_copy ;;
                    3) rule_03_docker_client ;;
                    4) rule_04_escape_attempt ;;
                    5) rule_05_cron_jobs ;;
                    6) rule_06_dynamic_linker ;;
                    7) rule_07_db_spawn ;;
                    8) rule_08_ssh_lateral ;;
                    9) rule_09_delete_history ;;
                    10) rule_10_discovery_tool ;;
                    11) rule_11_amicontained ;;
                    12) rule_12_disable_security ;;
                    13) rule_13_hugepages ;;
                    14) rule_14_crypto_miner ;;
                    15) rule_15_modify_shell ;;
                    16) rule_16_update_repo ;;
                    17) rule_17_read_ssh ;;
                    20) rule_20_terminal_shell ;;
                    22) rule_22_ec2_metadata ;;
                    23) rule_23_k8s_api ;;
                    24) rule_24_package_mgmt ;;
                    25) rule_25_netcat_rce ;;
                    26) rule_26_clear_logs ;;
                    27) rule_27_symlink ;;
                    32) rule_32_miner_termination ;;
                    33) rule_33_file_attrs ;;
                    34) rule_34_setuid ;;
                    35) rule_35_dangerous_delete ;;
                    36) rule_36_irc ;;
                    41) rule_41_search_secrets ;;
                    0) break ;;
                    *) print_error "Invalid option" ;;
                esac
            done
            ;;
        4)
            cleanup_resources
            ;;
        5)
            print_info "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
done
