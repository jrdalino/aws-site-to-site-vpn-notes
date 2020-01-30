# AWS Site-to-Site VPN Notes

## 1 Mock remote data center in another AWS Account/Region/Provider

### 1.1 Launch EC2 Instance in another AWS Account/Region
- VPC 10.0.0.0/16
- Launch in Public Subnet 10.1.0.0/24
- CentOS, m4.small instance
- Disable Source/Destination Check
- Configure Security Groups allow SSH from local workstation
- Assign Elastic IP
- UDP ports 4500 and UDP port 500

### 1.2 Install and Configure StrongSwan

- Install Strongswan
```
$ sudo yum install –y strongswan
```

- Enable IP forwarding
```
$ echo 1 > /proc/sys/net/ipv4/ip_forward && sudo sysctl –p
```

- Add entry in Routing table for Remote VPC CIDR Block 172.16.0.0/24

## 2 Configure AWS

### 2.1 Configure VPC
- CIDR:  172.16.0.0/24
- Public Subnet: 172.0.0.0/24
- Route table in entry 0.0.0.0/0 route to Internet Gateway 

### 2.2 Create a Customer Gateway
- VPC > Customer Gateways > Create Customer Gateway
- Name: Demo
- Routing: Static
- IP Address: XXX.XXX.XXX.XXX > Set the public IP address of the remote end of the VPN connection, i.e. the Elastic IP of the Remote Data Center's StrongSwan instance.
- Certfificate ARN: N/A
- Device: N/A

### 2.3 Create Virtual Private Gateway
- VPC > Virtual Private Gateway > Create Virtual Private Gateway
- Name: Demo
- ASN: Amazon default ASN

### 2.4 Attach VPC to VPC
- VPC > Virtual Private Gateway > Actions > Attach to VPC

### 2.5 Enable Route Propagation in your Route table
- Add entry in route table to point to VPG
- Enable route propagation in your route table
- For static routing, the static IP prefixes that you specify for your VPN configuration are propagated to the route table when the status of the Site-to-Site VPN connection is UP

### 2.6 Update Security Group
- Add Rules in Security Group to enable inbound SSH, RDP, ICMP, Access

### 2.7 Create Site to Site VPN Connection
- Name: Demo
- Target Gateway Type: Virtual Private Gateway
- Virtual Private Gateway: vgw-0c8e409fe0EXAMPLE
- Customer Gateway: Existing
- Customer Gateway ID: cgw-05ba9ee7d0EXAMPLE
- Routing Options: Static
- Static IP Prefixes: Set the CIDR block of your VPC you wish to make available over the VPN tunnel, e.g. 172.0.0.0/16 for the entire VPC network

## 3 Configure Remote Data Center VPN

### 3.1 Download Configuration File which we will use to configure your Customer Gateway Device
```
Amazon Web Services
Virtual Private Cloud

AWS utilizes unique identifiers to manipulate the configuration of
a VPN Connection. Each VPN Connection is assigned an identifier and is
associated with two other identifiers, namely the
Customer Gateway Identifier and Virtual Private Gateway Identifier.

Your VPN Connection ID                  : vpn-083f813b66c465acf
Your Virtual Private Gateway ID         : vgw-0e213adb654fb5e95
Your Customer Gateway ID                : cgw-0c5481d02fb9d5ccc


This configuration consists of two tunnels. Both tunnels must be configured on your Customer Gateway. If you are configuring your tunnels as policy-based, only a single tunnel may be up at a time. If you are configuring your tunnels as route-based, both tunnels may be up simultaneously. Please note this configuration file is intended for a route-based VPN solution. 

At this time this configuration has been tested for Strongswan 5.5.1 on the Ubuntu 16.04 LTS operating system, but may work with later versions as well. Due to an interoperational issue discovered with AWS VPN and earlier versions of Strongswan, it's not recommended to use a version prior to 5.5.1. 


--------------------------------------------------------------------------------------------------------------------
IPSEC Tunnel #1
--------------------------------------------------------------------------------------------------------------------
#1: Enable Packet Forwarding and Configure the Tunnel

This configuration assumes that you already have a default Strongswan 5.5.1+ installation in place on the Ubuntu 16.04 LTS operating system (but may work with other distros as well). It is not recommended to use a Strongswan version prior to 5.5.1. Please check which version your distro's repository has by default and install the latest stable release if necessary. 

1) Open /etc/sysctl.conf and uncomment the following line to enable IP packet forwarding:
   net.ipv4.ip_forward = 1
   
2) Apply the changes in step 1 by executing the command 'sudo sysctl -p'
 	
3) Create a new file at /etc/ipsec.conf if doesn't already exist, and then open it. Uncomment the line "uniqueids=no" under the 'config setup' section. Append the following configuration to the end of the file:

# AWS VPN will also support AES256 and SHA256 for the "ike" (Phase 1) and "esp" (Phase 2) entries below. 
# For Phase 1, AWS VPN supports DH groups 2, 14-18, 22, 23, 24. Phase 2 supports DH groups 2, 5, 14-18, 22, 23, 24
# To see Strongswan's syntax for these different values, please refer to https://wiki.strongswan.org/projects/strongswan/wiki/IKEv1CipherSuites
 
conn Tunnel1
	auto=start
	left=%defaultroute
	leftid=47.89.241.197
	right=15.188.41.231
	type=tunnel
	leftauth=psk
	rightauth=psk
	keyexchange=ikev1
	ike=aes128-sha1-modp1024
	ikelifetime=8h
	esp=aes128-sha1-modp1024
	lifetime=1h
	keyingtries=%forever
	leftsubnet=0.0.0.0/0
	rightsubnet=0.0.0.0/0
	dpddelay=10s
	dpdtimeout=30s
	dpdaction=restart
	## Please note the following line assumes you only have two tunnels in your Strongswan configuration file. This "mark" value must be unique and may need to be changed based on other entries in your configuration file.
	mark=100
	## Uncomment the following line to utilize the script from the "Automated Tunnel Healhcheck and Failover" section. Ensure that the integer after "-m" matches the "mark" value above, and <VPC CIDR> is replaced with the CIDR of your VPC
	## (e.g. 192.168.1.0/24)
	#leftupdown="/etc/ipsec.d/aws-updown.sh -ln Tunnel1 -ll 169.254.163.250/30 -lr 169.254.163.249/30 -m 100 -r <VPC CIDR>"
 		
4) Create a new file at /etc/ipsec.secrets if it doesn't already exist, and append this line to the file (be mindful of the spacing!). This value authenticates the tunnel endpoints:
47.89.241.197 15.188.41.231 : PSK "hygwCMlU3vlnNj5XnniE1a4okEXAMPLE"

5) If you would like to configure your route-based tunnels manually, please complete the following steps #2 - #5. These steps may be omitted if you decide to follow the steps in the "Automated Tunnel Healthcheck and Failover" section of the document.  

--------------------------------------------------------------------------------
#2: Tunnel Interface Configuration

A tunnel interface is a logical interface associated with tunnel traffic. All traffic to/from the VPC will be logically transmitted and received by the tunnel interface. 

1) If your device is in a VPC or behind a device performing NAT on your local network, replace <LOCAL IP> with the private IP of the device. Otherwise, use 47.89.241.197. The "key" value below MUST match the integer you placed as the "mark" value in your configuration file.

sudo ip link add Tunnel1 type vti local <LOCAL IP> remote 15.188.41.231 key 100
sudo ip addr add 169.254.163.250/30 remote 169.254.163.249/30 dev Tunnel1
sudo ip link set Tunnel1 up mtu 1419

2) Depending on how you plan to handle routing, you can optionally set up a static route pointing to your VPC for your new tunnel interface. Replace <VPC CIDR> with the CIDR of your VPC (e.g. 192.168.1.0/24):
sudo ip route add <VPC CIDR> dev Tunnel1 metric 100

3) By default, Strongswan will create a routing entry in a different route table at launch. To disable this feature and use the default route table:
- Open the file /etc/strongswan.d/charon.conf
- Uncomment the line "install_routes=yes"
- Change the value of the line to "install_routes=no"

--------------------------------------------------------------------------------
#3: iptables Configuration

iptables is a program designed to act as a firewall for the Linux kernel. It can be used to set up, maintain, and inspect packet filter values entered into several different tables.

iptables rules must be set when using tunnel interfaces so the Linux kernel knows to forward and accept packets on the logical interface. The "--set-xmark" value MUST match the integer you placed as the "mark" value in your configuration file.

sudo iptables -t mangle -A FORWARD -o Tunnel1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
sudo iptables -t mangle -A INPUT -p esp -s 15.188.41.231 -d 47.89.241.197 -j MARK --set-xmark 100

--------------------------------------------------------------------------------
#4: sysctl Modifications

In order to use your tunnel interface effectively, you will need to do some additional sysctl modifications.

1) Open /etc/sysctl.conf and append the following values to the end of the file. Replace <PHYSICAL INTERFACE> with the name of the physical interface your logical tunnel interface resides on (e.g. eth0). 
net.ipv4.conf.Tunnel1.rp_filter=2 #This value allows the Linux kernel to handle asymmetric routing
net.ipv4.conf.Tunnel1.disable_policy=1 #This value disables IPsec policy (SPD) for the interface
net.ipv4.conf.<PHYSICAL INTERFACE>.disable_xfrm=1 #This value disables crypto transformations on the physical interface
net.ipv4.conf.<PHYSICAL INTERFACE>.disable_policy=1 #This value disables IPsec policy (SPD) for the interface

2) Apply the changes in step 1 by executing the command 'sudo sysctl -p'

--------------------------------------------------------------------------------
#5: Persistent Configuration

Your tunnel interface is now ready for use, however if your device ever reboots the changes you've made will not persist. Complete the following steps so your changes will remain persistent after reboot.

1) Save your running iptables configuration by executing the command 'sudo iptables-save > /etc/iptables.conf'

2) Open /etc/rc.local and append the following to the end of the file, before the line 'exit 0':
iptables-restore < /etc/iptables.conf

3) Open /etc/network/interfaces and append the following to the end of the file. If your device is in a VPC or behind a device performing NAT on your local network, replace <LOCAL IP> with the private IP of the device. Otherwise, use 47.89.241.197. The "key" value below MUST match the integer you placed as the "mark" value in your configuration file.

auto Tunnel1
iface Tunnel1 inet manual
pre-up ip link add Tunnel1 type vti local <LOCAL IP> remote 15.188.41.231 key 100
pre-up ip addr add 169.254.163.250/30 remote 169.254.163.249/30 dev Tunnel1
up ip link set Tunnel1 up mtu 1419


--------------------------------------------------------------------------------------------------------------------
IPSEC Tunnel #2
--------------------------------------------------------------------------------------------------------------------
#1: Enable Packet Forwarding and Configure the Tunnel

This configuration assumes that you already have a default Strongswan 5.5.1+ installation in place on the Ubuntu 16.04 LTS operating system (but may work with other distros as well). It is not recommended to use a Strongswan version prior to 5.5.1. Please check which version your distro's repository has by default and install the latest stable release if necessary. 

1) Open /etc/sysctl.conf and uncomment the following line to enable IP packet forwarding:
   net.ipv4.ip_forward = 1
   
2) Apply the changes in step 1 by executing the command 'sudo sysctl -p'
 	
3) Create a new file at /etc/ipsec.conf if doesn't already exist, and then open it. Uncomment the line "uniqueids=no" under the 'config setup' section. Append the following configuration to the end of the file:

# AWS VPN will also support AES256 and SHA256 for the "ike" (Phase 1) and "esp" (Phase 2) entries below. 
# For Phase 1, AWS VPN supports DH groups 2, 14-18, 22, 23, 24. Phase 2 supports DH groups 2, 5, 14-18, 22, 23, 24
# To see Strongswan's syntax for these different values, please refer to https://wiki.strongswan.org/projects/strongswan/wiki/IKEv1CipherSuites
 
conn Tunnel2
	auto=start
	left=%defaultroute
	leftid=47.89.241.197
	right=15.188.104.185
	type=tunnel
	leftauth=psk
	rightauth=psk
	keyexchange=ikev1
	ike=aes128-sha1-modp1024
	ikelifetime=8h
	esp=aes128-sha1-modp1024
	lifetime=1h
	keyingtries=%forever
	leftsubnet=0.0.0.0/0
	rightsubnet=0.0.0.0/0
	dpddelay=10s
	dpdtimeout=30s
	dpdaction=restart
	## Please note the following line assumes you only have two tunnels in your Strongswan configuration file. This "mark" value must be unique and may need to be changed based on other entries in your configuration file.
	mark=200
	## Uncomment the following line to utilize the script from the "Automated Tunnel Healhcheck and Failover" section. Ensure that the integer after "-m" matches the "mark" value above, and <VPC CIDR> is replaced with the CIDR of your VPC
	## (e.g. 192.168.1.0/24)
	#leftupdown="/etc/ipsec.d/aws-updown.sh -ln Tunnel2 -ll 169.254.99.22/30 -lr 169.254.99.21/30 -m 200 -r <VPC CIDR>"
 		
4) Create a new file at /etc/ipsec.secrets if it doesn't already exist, and append this line to the file (be mindful of the spacing!). This value authenticates the tunnel endpoints:
47.89.241.197 15.188.104.185 : PSK "3uCYwNwR67gpjV1whEJs2Bb6zEXAMPLE"

5) If you would like to configure your route-based tunnels manually, please complete the following steps #2 - #5. These steps may be omitted if you decide to follow the steps in the "Automated Tunnel Healthcheck and Failover" section of the document.  

--------------------------------------------------------------------------------
#2: Tunnel Interface Configuration

A tunnel interface is a logical interface associated with tunnel traffic. All traffic to/from the VPC will be logically transmitted and received by the tunnel interface. 

1) If your device is in a VPC or behind a device performing NAT on your local network, replace <LOCAL IP> with the private IP of the device. Otherwise, use 47.89.241.197. The "key" value below MUST match the integer you placed as the "mark" value in your configuration file.

sudo ip link add Tunnel2 type vti local <LOCAL IP> remote 15.188.104.185 key 200
sudo ip addr add 169.254.99.22/30 remote 169.254.99.21/30 dev Tunnel2
sudo ip link set Tunnel2 up mtu 1419

2) Depending on how you plan to handle routing, you can optionally set up a static route pointing to your VPC for your new tunnel interface. Replace <VPC CIDR> with the CIDR of your VPC (e.g. 192.168.1.0/24):
sudo ip route add <VPC CIDR> dev Tunnel2 metric 200

3) By default, Strongswan will create a routing entry in a different route table at launch. To disable this feature and use the default route table:
- Open the file /etc/strongswan.d/charon.conf
- Uncomment the line "install_routes=yes"
- Change the value of the line to "install_routes=no"

--------------------------------------------------------------------------------
#3: iptables Configuration

iptables is a program designed to act as a firewall for the Linux kernel. It can be used to set up, maintain, and inspect packet filter values entered into several different tables.

iptables rules must be set when using tunnel interfaces so the Linux kernel knows to forward and accept packets on the logical interface. The "--set-xmark" value MUST match the integer you placed as the "mark" value in your configuration file.

sudo iptables -t mangle -A FORWARD -o Tunnel2 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
sudo iptables -t mangle -A INPUT -p esp -s 15.188.104.185 -d 47.89.241.197 -j MARK --set-xmark 200

--------------------------------------------------------------------------------
#4: sysctl Modifications

In order to use your tunnel interface effectively, you will need to do some additional sysctl modifications.

1) Open /etc/sysctl.conf and append the following values to the end of the file. Replace <PHYSICAL INTERFACE> with the name of the physical interface your logical tunnel interface resides on (e.g. eth0). 
net.ipv4.conf.Tunnel2.rp_filter=2 #This value allows the Linux kernel to handle asymmetric routing
net.ipv4.conf.Tunnel2.disable_policy=1 #This value disables IPsec policy (SPD) for the interface
net.ipv4.conf.<PHYSICAL INTERFACE>.disable_xfrm=1 #This value disables crypto transformations on the physical interface
net.ipv4.conf.<PHYSICAL INTERFACE>.disable_policy=1 #This value disables IPsec policy (SPD) for the interface

2) Apply the changes in step 1 by executing the command 'sudo sysctl -p'

--------------------------------------------------------------------------------
#5: Persistent Configuration

Your tunnel interface is now ready for use, however if your device ever reboots the changes you've made will not persist. Complete the following steps so your changes will remain persistent after reboot.

1) Save your running iptables configuration by executing the command 'sudo iptables-save > /etc/iptables.conf'

2) Open /etc/rc.local and append the following to the end of the file, before the line 'exit 0':
iptables-restore < /etc/iptables.conf

3) Open /etc/network/interfaces and append the following to the end of the file. If your device is in a VPC or behind a device performing NAT on your local network, replace <LOCAL IP> with the private IP of the device. Otherwise, use 47.89.241.197. The "key" value below MUST match the integer you placed as the "mark" value in your configuration file.

auto Tunnel2
iface Tunnel2 inet manual
pre-up ip link add Tunnel2 type vti local <LOCAL IP> remote 15.188.104.185 key 200
pre-up ip addr add 169.254.99.22/30 remote 169.254.99.21/30 dev Tunnel2
up ip link set Tunnel2 up mtu 1419


--------------------------------------------------------------------------------------------------------------------
Tunnel Heartbeat
--------------------------------------------------------------------------------------------------------------------

AWS VPN's Dead Peer Detection (DPD) function might tear down your tunnel if there is no interesting traffic detected on it. For this reason, it's recommended to have a heartbeat that periodically pings the remote endpoint's inside IP to keep the tunnel active. You can accomplish this with a simple bash script, for example:

1) Create a file heartbeat.sh and append the following to it:

#!/bin/bash

while true; do
	ping -c 1 $1 &> /dev/null
	ping -c 1 $2 &> /dev/null
	sleep 5
done

2) To make the file executable, run the command 'sudo chmod 744 heartbeat.sh'

3) When running the script, use your remote inside tunnel IP addresses (169.254.x) as inputs and keep it continuously running in the background. For example, you could run the below command replacing the values in <BRACKETS>:

./heartbeat.sh <REMOTE_INSIDE_IP_1> <REMOTE_INSIDE_IP_2> &

--------------------------------------------------------------------------------------------------------------------
Automated Tunnel Healthcheck and Failover
--------------------------------------------------------------------------------------------------------------------

Strongswan provides a built-in tunnel failover functionality known as the updown plugin. It allows you to define custom values when bringing the tunnels up and tearing them down. It also monitors the tunnel health and performs automatic failover in case of a failure. In the following example, you will create a script file that takes in parameters from your IPsec configuration file, parses them, and automates the processes listed in the IPsec tunnel configuration steps #2 - #5 above. 

Please keep in mind this solution is intended for Strongswan implementations set up as ROUTE-BASED only. This will not work for POLICY-BASED implementations. To better understand the differences, please refer to 
http://packetlife.net/blog/2011/aug/15/policy-based-vs-route-based-vpns-part-1/

=== DISCLAIMER ===
Please be aware that AWS is in no way responsible for any of the use, management, maintenance, or potential issues you may encounter with the following tunnel failover workaround. It is strongly recommended that you thoroughly test any failover solution prior to implementing it into your production environment.

This failover mechanism has been tested using Strongswan 5.5.1 and Ubuntu 16.04 LTS. 

=== HOW-TO ===
1) Create a new file at /etc/ipsec.d/aws-updown.sh if it doesn't already exist, and append the following script to the file:

#!/bin/bash

while [[ $# > 1 ]]; do
	case ${1} in
		-ln|--link-name)
			TUNNEL_NAME="${2}"
			TUNNEL_PHY_INTERFACE="${PLUTO_INTERFACE}"
			shift
			;;
		-ll|--link-local)
			TUNNEL_LOCAL_ADDRESS="${2}"
			TUNNEL_LOCAL_ENDPOINT="${PLUTO_ME}"
			shift
			;;
		-lr|--link-remote)
			TUNNEL_REMOTE_ADDRESS="${2}"
			TUNNEL_REMOTE_ENDPOINT="${PLUTO_PEER}"
			shift
			;;
		-m|--mark)
			TUNNEL_MARK="${2}"
			shift
			;;
		-r|--static-route)
			TUNNEL_STATIC_ROUTE="${2}"
			shift
			;;
		*)
			echo "${0}: Unknown argument \"${1}\"" >&2
			;;
	esac
	shift
done

command_exists() {
	type "$1" >&2 2>&2
}

create_interface() {
	ip link add ${TUNNEL_NAME} type vti local ${TUNNEL_LOCAL_ENDPOINT} remote ${TUNNEL_REMOTE_ENDPOINT} key ${TUNNEL_MARK}
	ip addr add ${TUNNEL_LOCAL_ADDRESS} remote ${TUNNEL_REMOTE_ADDRESS} dev ${TUNNEL_NAME}
	ip link set ${TUNNEL_NAME} up mtu 1419
}

configure_sysctl() {
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv4.conf.${TUNNEL_NAME}.rp_filter=2
	sysctl -w net.ipv4.conf.${TUNNEL_NAME}.disable_policy=1
	sysctl -w net.ipv4.conf.${TUNNEL_PHY_INTERFACE}.disable_xfrm=1
	sysctl -w net.ipv4.conf.${TUNNEL_PHY_INTERFACE}.disable_policy=1
}

add_route() {
	IFS=',' read -ra route <<< "${TUNNEL_STATIC_ROUTE}"
    	for i in "${route[@]}"; do
	    ip route add ${i} dev ${TUNNEL_NAME} metric ${TUNNEL_MARK}
	done
	iptables -t mangle -A FORWARD -o ${TUNNEL_NAME} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -t mangle -A INPUT -p esp -s ${TUNNEL_REMOTE_ENDPOINT} -d ${TUNNEL_LOCAL_ENDPOINT} -j MARK --set-xmark ${TUNNEL_MARK}
	ip route flush table 220
}

cleanup() {
        IFS=',' read -ra route <<< "${TUNNEL_STATIC_ROUTE}"
        for i in "${route[@]}"; do
            ip route del ${i} dev ${TUNNEL_NAME} metric ${TUNNEL_MARK}
        done
	iptables -t mangle -D FORWARD -o ${TUNNEL_NAME} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -t mangle -D INPUT -p esp -s ${TUNNEL_REMOTE_ENDPOINT} -d ${TUNNEL_LOCAL_ENDPOINT} -j MARK --set-xmark ${TUNNEL_MARK}
	ip route flush cache
}

delete_interface() {
	ip link set ${TUNNEL_NAME} down
	ip link del ${TUNNEL_NAME}
}

# main execution starts here

command_exists ip || echo "ERROR: ip command is required to execute the script, check if you are running as root, mostly to do with path, /sbin/" >&2 2>&2
command_exists iptables || echo "ERROR: iptables command is required to execute the script, check if you are running as root, mostly to do with path, /sbin/" >&2 2>&2
command_exists sysctl || echo "ERROR: sysctl command is required to execute the script, check if you are running as root, mostly to do with path, /sbin/" >&2 2>&2

case "${PLUTO_VERB}" in
	up-client)
		create_interface
		configure_sysctl
		add_route
		;;
	down-client)
		cleanup
		delete_interface
		;;
esac

2) To make the file executable, run the command 'sudo chmod 744 /etc/ipsec.d/aws-updown.sh'

3) Open the file /etc/ipsec.conf and ensure the "leftupdown" parameter at the end of each of your 'conn' entries is uncommented. You will need to modify <VPC CIDR> to match the CIDR of your VPC (e.g. 192.168.1.0/24). Please also verify the integer value after the "-m" option matches the "mark" parameter of your configuration if you have made changes to the default values of this configuration file. 

4) Restart the Strongswan daemon by executing the command 'sudo ipsec restart'

5) Check if your updown script worked properly. You can use the following commands to test if there are entries created for each of your tunnels:
- Execute 'sudo ipsec status' to ensure both of your tunnels are ESTABLISHED
- Execute 'sudo ip route' to ensure route table entires were created for each of your tunnel interfaces, and the destination is the remote VPC CIDR
- Execute 'sudo iptables -t mangle -L -n' to ensure entries were made for both of your tunnels in both the INPUT and FORWARD chains
- Execute 'ifconfig' to ensure the correct 169.254.x addresses were assigned to each end of your peer-to-peer virtual tunnel interfaces
- Attempt to ping a destination in the remote VPC from a host within your local network. If there is no response, check to see if your instance's security groups are allowing traffic and verify your settings entered above are correct once again

6) Verify failover is working properly. You can test this by blocking traffic from the remote virtual private gateway (VGW) public IPs. For example:
sudo iptables -A INPUT -s <VGW PUBLIC IP> -j DROP


  Additional Notes and Questions
  - Amazon Virtual Private Cloud Getting Started Guide:
        http://docs.amazonwebservices.com/AmazonVPC/latest/GettingStartedGuide
  - Amazon Virtual Private Cloud Network Administrator Guide:
        http://docs.amazonwebservices.com/AmazonVPC/latest/NetworkAdminGuide
  - XSL Version: 2009-07-15-1119716
```

### 3.2 SSH to Remote Data Center VPN to configure StrongSwan tunnels
```
$ vi /etc/strongswan/ipsec.conf
```
```
# Add connections here.
# Sample VPN connections
conn %default
        ikelifetime=28800s
        keylife=3600s
        rekeymargin=3m
        keyingtries=3
        dpddelay=10s
        dpdtimeout=30s
        authby=secret
        mobike=no
conn toawstunnel1
        keyexchange=ikev1
        left=10.1.0.55
        leftsubnet=10.1.0.0/24
        leftid=47.89.241.197
        right=35.160.16.102
        rightsubnet=172.0.0.0/24
        rightid=35.160.16.102
        dpdaction=restart
        auto=route
        esp=aes128-sha1-modp1024
        lifetime=3600
        ike=aes128-sha1-modp1024
        ikelifetime=28800s
        type=tunnel

conn toawstunnel2
        keyexchange=ikev1
        left=10.1.0.55
        leftsubnet=10.1.0.0/24
        leftid=47.89.241.197
        right=35.160.48.137
        rightsubnet=172.0.0.0/24
        rightid=35.160.48.137
        dpdaction=restart
        auto=route
        esp=aes128-sha1-modp1024
        lifetime=3600
        ike=aes128-sha1-modp1024
        ikelifetime=28800s
        type=tunnel
```

### 3.3 Configure the secret keys /etc/strongswan/ipsec.secrets
```
47.89.241.197 35.160.16.102 : PSK "put_your_PSK_here_xxxxxxxxxxxxxxxxxxxx"
47.89.241.197 35.160.48.137 : PSK "put_your_PSK_here_xxxxxxxxxxxxxxxxxxx"
```

### 3.4 Restart strongSwan and make sure service is running
```
$ systemctl restart strongswan.service
$ systemctl status strongswan.service
```

## 4 Test the VPN Tunnel

### 4.1 Launch another EC2 Instance in remote data center and EC2 Instance in AWS
```
[ec2-user@10-1-0-0-15 ~]$ ping 172.0.0.80 
64 bytes from 172.0.0.80: icmp_seq=1 ttl=63 time=26.1 ms
64 bytes from 172.0.0.80: icmp_seq=2 ttl=63 time=26.2 ms
64 bytes from 172.0.0.80: icmp_seq=3 ttl=63 time=26.0 ms
64 bytes from 172.0.0.80: icmp_seq=4 ttl=63 time=26.0 ms
```

### 4.2 Validate by checking AWS VPN Connection Tunnel Status on console. The status of one tunnel should be "UP".

## 5 Improve Security of Security Groups to permit public traffic necessary to setup the IPSec tunnel
```
Type            Protocol Port Range Source
----		-------- ---------- ------
All traffic     All      All        10.0.1.0/24
All traffic     All      All        172.0.0.0/16
Custom UDP Rule UDP      4500       35.160.16.102/32
Custom UDP Rule UDP      500        35.160.48.137/32
```

## References: 
- https://www.peternijssen.nl/connect-multiple-aws-regions-strongswan/
- https://geekdudes.wordpress.com/2019/01/30/creating-site-to-site-vpn-between-strongswan-and-amazon-aws-virtual-private-gateway/
- https://www.alibabacloud.com/blog/connecting-alibaba-cloud-to-aws-with-high-availability-vpn_594329
