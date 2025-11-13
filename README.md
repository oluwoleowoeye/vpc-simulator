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
sudo ./vpcctl.sh


```markdown
## 💻 Usage Examples

### Basic VPC Setup
```bash
# Make script executable
chmod +x vpcctl.sh

# Run full setup (requires sudo)
sudo ./vpcctl.sh

# Test web tier connectivity
sudo ip netns exec web_ns ping 10.0.2.10

# Check security rules
sudo ip netns exec web_ns iptables -L -n

# Verify VPC peering
ping -I vpc0 10.10.0.1


