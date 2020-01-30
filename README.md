# AWS Site-to-site VPN Notes

## (Prerequisites for testing) Launch EC2 Instance in another AWS Account/Region
- Linux, m4.large instance
- Launch in Public Subnet
- Disable Source/Destination Check
- Assign Elastic IP
- Configure Seurity Groups, SSH
- UDP ports 4500 and UDP port 500

## Install and Configure StrongSwan

- Install Strongswan
```
$ yum install epel-release
$ yum install strongswan
$ vi /etc/strongswan/ipsec.conf
```

- EC2 on VPC 1
```
config setup
  strictcrlpolicy=no
  charondebug=all
conn %default
  ikelifetime=60m
  keylife=20m
  rekeymargin=3m
  keyingtries=1
  keyexchange=ikev2
conn Tunnel1
  authby=secret
  auto=start
  type=tunnel
  left=10.0.1.198
  leftid=52.213.124.101
  leftsubnet=10.0.0.0/16
  leftauth=psk
  right=35.156.123.101
  rightsubnet=10.10.0.0/16
  rightauth=psk
  ike=aes128-sha1-modp1024
  esp=aes128-sha1-modp1024
```

- Secure connection with PSK
```
$ vi /etc/strongswan/ipsec.secrets
```
```
52.213.124.101 : PSK "Dl8EDinVF8L0Y2Ot7GbSWlby9D1vDkVB3d4nxV1dQmGeM137xgF3KhQ4CQC8hXGu"
```

-  Configure port fowarding on both machines
```
$ vi /etc/sysctl.conf.

```
```
net.ipv4.ip_forward=1
```
```
$ sysctl -p
```

- Restart Services
```
$ service strongswan restart
$ ipsec stop
$ ipsec start
```

- Check Status
```
$ ipsec status
```

## 1 Create a Customer Gateway
- VPC > Customer Gateways > Create Customer Gateway
- Name: Demo
- Routing: Static
- IP Address: XXX.XXX.XXX.XXX > Specify the Internet-routable IP address for your gateway's external interface; the address must be static and may be behind a device performing network address translation (NAT).
- Certfificate ARN: N/A
- Device: N/A

## 2 Create Virtual Private Gateway
- VPC > Virtual Private Gateway > Create Virtual Private Gateway
- Name: Demo
- ASN: Amazon default ASN

## 3 Attach VPC to VPC
- VPC > Virtual Private Gateway > Actions > Attach to VPC

## 4 Enable Route Propagation in your Route table
- Add entry in route table to point to VPG
- Enable route propagation in your route table
- For static routing, the static IP prefixes that you specify for your VPN configuration are propagated to the route table when the status of the Site-to-Site VPN connection is UP

## 5 Update Security Group
- Add Rules in Security Group to enable inbound SSH, RDP, ICMP, Access

## 6 Create Site to Site VPN Connection
- Name: Demo
- Target Gateway Type: Virtual Private Gateway
- Virtual Private Gateway: vgw-0c8e409fe0EXAMPLE
- Customer Gateway: Existing
- Customer Gateway ID: cgw-05ba9ee7d0EXAMPLE
- Routing Options: Static
- Static IP Prefixes: X.X.X.X/XX

## 7 Download Configuration File which we will use to configure your Customer Gateway Device
```
Amazon Web Services
Virtual Private Cloud

AWS utilizes unique identifiers to manipulate the configuration of a VPN Connection. Each VPN Connection is assigned an identifier and is associated with two other identifiers, namely the Customer Gateway Identifier and Virtual Private Gateway Identifier.

Your VPN Connection ID                  : vpn-0999ab4ae3EXAMPLE
Your Virtual Private Gateway ID         : vgw-0c8e409fe0EXAMPLE
Your Customer Gateway ID                : cgw-05ba9ee7d0EXAMPLE

This configuration consists of two tunnels. Both tunnels must be configured on your Customer Gateway, but only one of those tunnels should be up at any given time.

At this time this configuration has only been tested for Openswan 2.6.38 or later, but may work with earlier versions.

--------------------------------------------------------------------------------------------------------------------
IPSEC Tunnel #1
--------------------------------------------------------------------------------------------------------------------

This configuration assumes that you already have a default openswan installation in place on the Amazon Linux operating system (but may also work with other distros as well)

1) Open /etc/sysctl.conf and ensure that its values match the following:
   net.ipv4.ip_forward = 1
   net.ipv4.conf.default.rp_filter = 0
   net.ipv4.conf.default.accept_source_route = 0
   
2) Apply the changes in step 1 by executing the command 'sysctl -p'

3) Open /etc/ipsec.conf and look for the line below. Ensure that the # in front of the line has been removed, then save and exit the file.
    #include /etc/ipsec.d/*.conf
 	
4) Create a new file at /etc/ipsec.d/aws.conf if doesn't already exist, and then open it. Append the following configuration to the end in the file:
 #leftsubnet= is the local network behind your openswan server, and you will need to replace the <LOCAL NETWORK> below with this value (don't include the brackets). If you have multiple subnets, you can use 0.0.0.0/0 instead.
 #rightsubnet= is the remote network on the other side of your VPN tunnel that you wish to have connectivity with, and you will need to replace <REMOTE NETWORK> with this value (don't include brackets).
 
conn Tunnel1
	authby=secret
	auto=start
	left=%defaultroute
	leftid=1.1.1.1
	right=35.181.12.73
	type=tunnel
	ikelifetime=8h
	keylife=1h
	phase2alg=aes128-sha1;modp1024
	ike=aes128-sha1;modp1024
	auth=esp
	keyingtries=%forever
	keyexchange=ike
	leftsubnet=<LOCAL NETWORK>
	rightsubnet=<REMOTE NETWORK>
	dpddelay=10
	dpdtimeout=30
	dpdaction=restart_by_peer
 		
5) Create a new file at /etc/ipsec.d/aws.secrets if it doesn't already exist, and append this line to the file (be mindful of the spacing!):
1.1.1.1 35.181.12.73: PSK "EXAMPLE"

--------------------------------------------------------------------------------------------------------------------
IPSEC Tunnel #2
--------------------------------------------------------------------------------------------------------------------

This configuration assumes that you already have a default openswan installation in place on the Amazon Linux operating system (but may also work with other distros as well)

1) Open /etc/sysctl.conf and ensure that its values match the following:
   net.ipv4.ip_forward = 1
   net.ipv4.conf.default.rp_filter = 0
   net.ipv4.conf.default.accept_source_route = 0
   
2) Apply the changes in step 1 by executing the command 'sysctl -p'

3) Open /etc/ipsec.conf and look for the line below. Ensure that the # in front of the line has been removed, then save and exit the file.
    #include /etc/ipsec.d/*.conf
 	
4) Create a new file at /etc/ipsec.d/aws.conf if doesn't already exist, and then open it. Append the following configuration to the end in the file:
 #leftsubnet= is the local network behind your openswan server, and you will need to replace the <LOCAL NETWORK> below with this value (don't include the brackets). If you have multiple subnets, you can use 0.0.0.0/0 instead.
 #rightsubnet= is the remote network on the other side of your VPN tunnel that you wish to have connectivity with, and you will need to replace <REMOTE NETWORK> with this value (don't include brackets).
 
conn Tunnel2
	authby=secret
	auto=start
	left=%defaultroute
	leftid=1.1.1.1
	right=52.47.142.8
	type=tunnel
	ikelifetime=8h
	keylife=1h
	phase2alg=aes128-sha1;modp1024
	ike=aes128-sha1;modp1024
	auth=esp
	keyingtries=%forever
	keyexchange=ike
	leftsubnet=<LOCAL NETWORK>
	rightsubnet=<REMOTE NETWORK>
	dpddelay=10
	dpdtimeout=30
	dpdaction=restart_by_peer
 		
5) Create a new file at /etc/ipsec.d/aws.secrets if it doesn't already exist, and append this line to the file (be mindful of the spacing!):
1.1.1.1 52.47.142.8: PSK "EXAMPLE"
```

## Refernces: 
- https://www.peternijssen.nl/connect-multiple-aws-regions-strongswan/
- https://geekdudes.wordpress.com/2019/01/30/creating-site-to-site-vpn-between-strongswan-and-amazon-aws-virtual-private-gateway/
