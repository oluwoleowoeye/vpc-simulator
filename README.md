# VPC Simulator

**VPC networking implemented with Linux bridges, namespaces, and iptables**

## Prerequisites
- Linux environment
- sudo privileges  
- `jq` installed (`sudo apt-get install jq`)
- Basic networking knowledge

##  Quick Start

```bash
# Clone and run
git clone <your-repo-url>
cd vpc-simulator

```markdown
## 💻 Usage Examples

### Basic VPC Setup
```bash
# Make script executable
chmod +x vpcctl.sh

# 1. Create VPCs
sudo ./vpcctl.sh create vpc vpc0 10.0.0.1/16 10.0.0.0/16
sudo ./vpcctl.sh create vpc vpc1 10.10.0.1/16 10.10.0.0/16

# 2. Enable NAT for internet access
sudo ./vpcctl.sh enable nat vpc0 10.0.0.0/16

# 3. Add subnets
sudo ./vpcctl.sh add subnet web_ns 10.0.1.0/24 public vpc0
sudo ./vpcctl.sh add subnet db_ns 10.0.2.0/24 private vpc0
sudo ./vpcctl.sh add subnet app_ns 10.10.1.0/24 public vpc1

# 4. Peer the VPCs
sudo ./vpcctl.sh peer vpcs vpc0 10.0.0.0/16 vpc1 10.10.0.0/16

# Test internet access
sudo ./vpcctl.sh test internet web_ns
sudo ./vpcctl.sh test internet app_ns

# Test cross-subnet communication
sudo ./vpcctl.sh test subnet_to_subnet web_ns db_ns

# Test cross-VPC peering
sudo ./vpcctl.sh test subnet_to_subnet web_ns app_ns

# Remove all VPCs, subnets, and network configuration
sudo ./vpcctl.sh clean
