# goatherd
Packet Capture and Analysis tool for identifying downstream subnets

## what does it do?

GOatherd analyzes tcp/ip communications (either live on the wire, or from a previously captured .pcap file) and assesses their source ARP and IP addresses with XOR bitwise pattern matching to make an intelligent attempt to determine:
* what addresses on your local network are the 'downstream' gateways (gateways from other networks), and which one (at minimum) is the 'upstream' gateway (ie the gateway address for the local subnet).
* To the best of its abilities, what CIDR subnets are 'downstream' from the local network (incoming to it from one or more layers of downstream gateways). 
