export interface TermDefinition {
  term: string;
  description: string;
}

export const coreTerms: TermDefinition[] = [
  {
    term: 'OSI Model',
    description: 'The Open Systems Interconnection (OSI) model is a conceptual framework used to understand and standardize the functions of a telecommunication or computing system without regard to its underlying internal technology and specific protocols. It divides network communication into seven distinct layers: Physical, Data Link, Network, Transport, Session, Presentation, and Application. SOC analysts use this model to pinpoint where an attack or security event is occurring (e.g., a Layer 7 attack).',
  },
  {
    term: 'TCP/IP Model',
    description: 'The Transmission Control Protocol/Internet Protocol (TCP/IP) model is the practical, four-layer protocol stack used by the internet and most modern networks. It simplifies the OSI model into four layers: Network Access, Internet, Transport, and Application. This model is essential for SOC analysts when performing packet analysis and configuring firewall rules, as it directly maps to real-world protocols like HTTP, TCP, and IP.',
  },
  {
    term: 'IP Address',
    description: 'An Internet Protocol (IP) address is a unique numerical label assigned to every device connected to a computer network that uses the Internet Protocol for communication. It serves two main functions: host or network interface identification and location addressing. In the SOC, IP addresses are crucial Indicators of Compromise (IOCs) used to track the source and destination of malicious traffic.',
  },
  {
    term: 'MAC Address',
    description: 'A Media Access Control (MAC) address is a unique identifier assigned to a network interface controller (NIC) for use as a network address in communications within a network segment. Unlike IP addresses, which are logical and can change, MAC addresses are physical and hardcoded by the manufacturer. They are used by SOC analysts for local network forensics and Network Access Control (NAC) enforcement.',
  },
  {
    term: 'Subnet Mask',
    description: 'A subnet mask is a 32-bit number used in conjunction with an IP address to divide the IP address into two parts: the network address and the host address. This process, called subnetting, allows a large network to be broken down into smaller, more manageable segments (subnets). SOC teams use subnet masks to define network boundaries and enforce segmentation policies.',
  },
  {
    term: 'DHCP',
    description: 'The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on IP networks for dynamically assigning IP addresses and other network configuration parameters (like subnet mask and default gateway) to devices. DHCP logs are vital for SOC investigations, as they link a specific IP address at a specific time to a MAC address, helping identify the compromised host.',
  },
  {
    term: 'DNS',
    description: 'The Domain Name System (DNS) is the hierarchical and decentralized naming system used to translate human-readable domain names (like google.com) into machine-readable IP addresses. DNS is a frequent target and vector for attacks (e.g., DNS tunneling, domain hijacking), making DNS logs a critical data source for threat detection and hunting.',
  },
  {
    term: 'VPN',
    description: 'A Virtual Private Network (VPN) extends a private network across a public network, enabling users to send and receive data across shared or public networks as if their computing devices were directly connected to the private network. VPNs are essential for secure remote access, but VPN logs must be monitored closely for suspicious activity like impossible travel or brute force attacks.',
  },
  {
    term: 'Firewall',
    description: 'A firewall is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. Next-Generation Firewalls (NGFWs) go beyond simple port/protocol filtering to include deep packet inspection, intrusion prevention, and application control. Firewalls are the primary perimeter defense tool for blocking external threats.',
  },
  {
    term: 'IDS/IPS',
    description: 'Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) monitor network or system activity for malicious activity or policy violations. An IDS passively detects threats and generates alerts, while an IPS actively attempts to stop the threat (e.g., by dropping malicious packets or resetting connections). They are crucial for detecting network-based attacks like port scans and exploit attempts.',
  },
  {
    term: 'SIEM',
    description: 'Security Information and Event Management (SIEM) is a software solution that aggregates and analyzes data from various security and log sources across an organization\'s infrastructure. It provides real-time correlation, alerting, and historical analysis, serving as the central nervous system of the SOC for incident detection and compliance reporting.',
  },
  {
    term: 'SSL/TLS',
    description: 'Secure Sockets Layer (SSL) and its successor, Transport Layer Security (TLS), are cryptographic protocols designed to provide communications security over a computer network. They are widely used to secure web traffic (HTTPS) and other applications, ensuring data integrity and confidentiality. SOC teams must monitor for outdated or improperly configured SSL/TLS versions.',
  },
  {
    term: 'Encryption',
    description: 'Encryption is the process of encoding information or data in such a way that only authorized parties can access it and those who are not authorized cannot. It is a fundamental security control for protecting data both in transit and at rest. SOC analysts often look for unauthorized encryption activity (e.g., ransomware) or attempts to bypass encryption controls.',
  },
  {
    term: 'VPN Tunneling',
    description: 'VPN tunneling is the process by which data packets are encapsulated within another protocol (the tunnel) and encrypted before being sent over a public network. This creates a secure, private connection between two points. Security teams monitor tunneling activity for signs of unauthorized data exfiltration or covert communication channels.',
  },
  {
    term: 'Port Scanning',
    description: 'Port scanning is a technique used by attackers to systematically probe a server or host for open ports, which indicates active services that could be exploited. It is a common reconnaissance tactic and is typically detected and alerted upon by IDS/IPS and firewall systems.',
  },
  {
    term: 'VLAN',
    description: 'A Virtual Local Area Network (VLAN) is a logical subdivision of a physical network. VLANs allow network administrators to segment a single physical switch into multiple virtual switches, isolating traffic between different groups of devices (e.g., separating guest Wi-Fi from corporate servers). This is a key technique for network segmentation and limiting lateral movement during an attack.',
  },
  {
    term: 'NAT',
    description: 'Network Address Translation (NAT) is a method of remapping an IP address space into another by modifying network address information in the IP header of packets while they are in transit. It is commonly used to allow multiple devices on a private network to share a single public IP address when connecting to the internet. NAT logs are essential for tracing external connections back to the internal source host.',
  },
  {
    term: 'Proxy Server',
    description: 'A proxy server acts as an intermediary for requests from clients seeking resources from other servers. It can be used for security (filtering malicious content), performance (caching), or privacy (masking client IP addresses). SOC teams rely heavily on proxy logs to monitor outbound web traffic, enforce acceptable use policies, and detect connections to malicious domains.',
  },
  {
    term: 'Packet Sniffing',
    description: 'Packet sniffing (or network analysis) is the practice of monitoring and capturing all data packets passing through a given network using a software application or hardware device. While legitimate for troubleshooting, attackers use it to capture sensitive information like unencrypted credentials. SOC analysts use tools like Wireshark or tcpdump for deep forensic analysis of network traffic.',
  },
  {
    term: 'DDoS Protection',
    description: 'Distributed Denial-of-Service (DDoS) protection refers to the measures and services implemented to protect a network, server, or application from being overwhelmed by a flood of malicious traffic. This typically involves rate limiting, traffic scrubbing, and leveraging cloud-based mitigation services to ensure service availability.',
  },
  {
    term: 'Bandwidth',
    description: 'Bandwidth refers to the maximum rate of data transfer across a given path, typically measured in bits per second (bps). In a security context, monitoring bandwidth usage is critical for detecting anomalies like massive data exfiltration attempts or DDoS attacks, which cause sudden, unusual spikes in traffic volume.',
  },
  {
    term: 'Latency',
    description: 'Latency is the delay before a transfer of data begins following an instruction for its transfer, often measured in milliseconds. High latency can indicate network congestion, routing issues, or, in a security context, a compromised system communicating with a distant Command and Control (C2) server, although it is usually a performance metric.',
  },
  {
    term: 'Load Balancer',
    description: 'A load balancer is a device or service that distributes network or application traffic across multiple servers in a server farm. This ensures no single server is overwhelmed, improving responsiveness and availability. Load balancer logs are important for tracking the true source IP of a request before it hits the application server.',
  },
  {
    term: 'Content Filter',
    description: 'A content filter is software that screens and restricts the content delivered over the web to a user, often based on categories (e.g., malware, pornography, gambling). SOC teams use content filters (often integrated into proxies or firewalls) to prevent users from accessing known malicious websites and enforce corporate policies.',
  },
  {
    term: 'SSL Inspection',
    description: 'SSL/TLS inspection (or decryption) is the process where a security device (like a firewall or proxy) decrypts encrypted traffic, inspects the content for threats (e.g., malware, policy violations), and then re-encrypts it before sending it to the destination. This is essential for detecting threats hidden within encrypted traffic, but it requires careful management of cryptographic keys.',
  },
  {
    term: 'ACL (Access Control List)',
    description: 'An Access Control List (ACL) is a set of rules that controls the incoming and outgoing network traffic on a device (like a router or firewall) based on criteria such as source/destination IP address, protocol, and port number. ACLs are a foundational security mechanism used to enforce network segmentation and least privilege access.',
  },
  {
    term: 'ARP (Address Resolution Protocol)',
    description: 'The Address Resolution Protocol (ARP) is a communication protocol used to map an IP address to a physical MAC address on a local area network (LAN). ARP is vulnerable to ARP spoofing attacks, where an attacker sends false ARP messages to link their MAC address with a legitimate IP address, allowing them to intercept traffic (Man-in-the-Middle).',
  },
  {
    term: 'BGP (Border Gateway Protocol)',
    description: 'The Border Gateway Protocol (BGP) is the routing protocol that makes the internet work. It manages how packets are routed from one autonomous system (large network) to another by exchanging routing and reachability information. BGP hijacking, where an attacker falsely advertises ownership of IP prefixes, is a critical external threat monitored by threat intelligence teams.',
  },
  {
    term: 'Botnet',
    description: 'A botnet is a network of private computers infected with malicious software (bots) and controlled remotely by a threat actor (bot-herder). Botnets are typically used to carry out large-scale attacks, such as DDoS attacks, spam campaigns, or credential stuffing. Detecting C2 communication is key to identifying botnet members within an organization.',
  },
  {
    term: 'CIDR (Classless Inter-Domain Routing)',
    description: 'Classless Inter-Domain Routing (CIDR) is a method for allocating IP addresses and routing IP packets more efficiently than the older classful system. CIDR notation (e.g., 192.168.1.0/24) is used extensively in firewall rules and network configuration to define IP address ranges.',
  },
  {
    term: 'DDoS (Distributed Denial of Service)',
    description: 'A Distributed Denial of Service (DDoS) attack attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of Internet traffic originating from multiple compromised computer systems (a botnet). SOC teams respond by activating DDoS mitigation services and blocking source IPs.',
  },
  {
    term: 'DHCP (Dynamic Host Configuration Protocol)',
    description: 'A network management protocol used on IP networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network. DHCP logs are crucial for SOC investigations, as they link a specific IP address at a specific time to a MAC address, helping identify the compromised host.',
  },
  {
    term: 'DNS (Domain Name System)',
    description: 'The hierarchical and decentralized naming system used to identify computers, services, and other resources reachable through the internet or other IP networks by translating human-friendly domain names to machine-readable IP addresses. DNS is a frequent target and vector for attacks (e.g., DNS tunneling, domain hijacking), making DNS logs a critical data source for threat detection and hunting.',
  },
  {
    term: 'DPI (Deep Packet Inspection)',
    description: 'Deep Packet Inspection (DPI) is an advanced form of network packet filtering that examines the data payload of a packet, not just the header (source, destination, port). DPI is used by NGFWs and IPS systems to identify application usage, detect embedded malware, and enforce granular security policies that traditional firewalls cannot.',
  },
  {
    term: 'EDR (Endpoint Detection and Response)',
    description: 'Endpoint Detection and Response (EDR) is a cybersecurity technology that continuously monitors and records endpoint activity (workstations, servers) to detect, investigate, and respond to advanced threats. EDR provides the granular visibility needed for threat hunting, root cause analysis, and automated response actions like host isolation and process termination.',
  },
  {
    term: 'Firewall',
    description: 'A network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. Firewalls are the primary perimeter defense tool for blocking external threats and enforcing internal network segmentation policies.',
  },
  {
    term: 'Honeypot',
    description: 'A honeypot is a security resource intended to be probed, attacked, or compromised. It is essentially a decoy system set up to attract and trap cyber attackers, allowing the SOC team to gather intelligence on the attacker\'s tactics, techniques, and procedures (TTPs) without risking production systems.',
  },
  {
    term: 'IDS (Intrusion Detection System)',
    description: 'An Intrusion Detection System (IDS) is a device or software application that monitors a network or systems for malicious activity or policy violations and generates alerts when suspicious activity is detected. It operates passively, meaning it does not actively block traffic but provides crucial visibility for the SOC team.',
  },
  {
    term: 'IPS (Intrusion Prevention System)',
    description: 'An Intrusion Prevention System (IPS) is an extension of an IDS that actively works to prevent identified threats. When a threat is detected, the IPS can automatically take action, such as dropping the malicious packet, blocking the source IP address, or resetting the connection. It is deployed inline with network traffic.',
  },
  {
    term: 'IPv4/IPv6',
    description: 'Internet Protocol version 4 (IPv4) and version 6 (IPv6) are the two versions of the Internet Protocol used to identify devices on a network. IPv4 uses 32-bit addresses (e.g., 192.168.1.1), while IPv6 uses 128-bit addresses, providing a vastly larger address space to accommodate the growing number of internet-connected devices. SOC tools must support both protocols for comprehensive monitoring.',
  },
  {
    term: 'MAC Address (Media Access Control Address)',
    description: 'A unique identifier assigned to a network interface controller (NIC) for use as a network address in communications within a network segment. MAC addresses are physical and hardcoded by the manufacturer. They are used by SOC analysts for local network forensics and Network Access Control (NAC) enforcement.',
  },
  {
    term: 'Malware',
    description: 'Malware (malicious software) is any software intentionally designed to cause damage to a computer, server, client, or computer network. This includes viruses, worms, ransomware, spyware, and trojans. EDR and SIEM systems are primarily focused on detecting and eradicating malware infections.',
  },
  {
    term: 'NAT (Network Address Translation)',
    description: 'Network Address Translation (NAT) is a method of remapping one IP address space into another by modifying network address information in the IP header of packets while they are in transit across a traffic routing device. NAT logs are essential for tracing external connections back to the internal source host.',
  },
  {
    term: 'NIDS (Network Intrusion Detection System)',
    description: 'A Network Intrusion Detection System (NIDS) analyzes incoming network traffic to identify any suspicious patterns that may indicate a network or system attack. NIDS typically relies on signature matching and anomaly detection to monitor traffic flowing across network segments.',
  },
  {
    term: 'NIPS (Network Intrusion Prevention System)',
    description: 'A Network Intrusion Prevention System (NIPS) is deployed inline to actively monitor and block network attacks by dropping detected malicious traffic. NIPS is a critical component of perimeter defense, often integrated into Next-Generation Firewalls.',
  },
  {
    term: 'OSI Model (Open Systems Interconnection Model)',
    description: 'A conceptual framework used to understand and standardize the functions of a telecommunication or computing system without regard to its underlying internal technology and specific protocols. It divides network communication into seven distinct layers: Physical, Data Link, Network, Transport, Session, Presentation, and Application.',
  },
  {
    term: 'Packet Sniffing',
    description: 'The practice of monitoring and capturing all data packets passing through a given network using a software application or hardware device. Attackers use it to capture sensitive information like unencrypted credentials. SOC analysts use tools like Wireshark or tcpdump for deep forensic analysis of network traffic.',
  },
  {
    term: 'Phishing',
    description: 'Phishing is a cyber attack employing deceptive communications, typically email, aimed at tricking individuals into revealing personal information, installing malware, or opening links to infected websites. SOC teams use Email Security Gateways (ESG) and user awareness training to mitigate phishing risks.',
  },
  {
    term: 'Ransomware',
    description: 'Ransomware is a type of malicious software designed to block access to a computer system or data, typically by encrypting it, until a sum of money (ransom) is paid. EDR systems are crucial for detecting the behavioral patterns of ransomware (e.g., mass file encryption) and initiating immediate containment.',
  },
  {
    term: 'SIEM (Security Information and Event Management)',
    description: 'A set of integrated tools designed to provide a comprehensive and real-time view of the security posture of an organization by collecting, analyzing, and presenting security data from various sources. It is the central platform for incident detection, correlation, and compliance reporting.',
  },
  {
    term: 'SSL/TLS (Secure Sockets Layer / Transport Layer Security)',
    description: 'Cryptographic protocols designed to provide communications security over a computer network, widely used for web browsers and other applications that require data to be securely exchanged.',
  },
  {
    term: 'Subnet',
    description: 'A logical subdivision of an IP network, breaking down a large network into smaller, manageable pieces. Subnetting improves network efficiency and is a key component of network segmentation for security purposes.',
  },
  {
    term: 'TCP/IP (Transmission Control Protocol/Internet Protocol)',
    description: 'The basic communication language or set of protocols for the Internet. It is the practical, four-layer model used for data transmission, focusing on end-to-end connectivity and routing.',
  },
  {
    term: 'Threat Intelligence',
    description: 'Evidence-based knowledge, including context, mechanisms, indicators, implications, and actionable advice, about an existing or emerging menace or hazard. Threat intelligence feeds (IOCs) are integrated into SIEM and EDR tools to proactively detect known malicious IPs, domains, and file hashes.',
  },
  {
    term: 'VLAN (Virtual Local Area Network)',
    description: 'A method to create independent networks within a physical network, improving the management and security of data traffic by isolating different groups of devices. VLANs are essential for enforcing network segmentation policies.',
  },
  {
    term: 'VPN (Virtual Private Network)',
    description: 'A service that encrypts your internet traffic and protects your online identity by hiding your IP address, making your internet activity more secure. VPN logs are critical for monitoring remote access security.',
  },
  {
    term: 'WAF (Web Application Firewall)',
    description: 'A Web Application Firewall (WAF) is a specific type of application firewall that filters, monitors, and blocks HTTP traffic to and from a web service. WAFs are designed to protect web applications from common attacks like SQL injection, Cross-Site Scripting (XSS), and unauthorized file uploads.',
  },
  {
    term: 'XSS (Cross-Site Scripting)',
    description: 'Cross-Site Scripting (XSS) is a security vulnerability typically found in web applications that allows attackers to inject malicious client-side scripts into web pages viewed by other users. WAFs are often configured to detect and block XSS payloads.',
  },
  {
    term: 'Zero Day',
    description: 'A zero-day vulnerability is a flaw in software, hardware, or firmware that is unknown to the vendor or the public, meaning there is no patch available. A zero-day exploit is an attack that leverages this vulnerability before the vendor can release a fix, making them highly dangerous and difficult to detect without behavioral monitoring.',
  },
  {
    term: 'MITM (Man In The Middle Attack)',
    description: 'A Man-in-the-Middle (MITM) attack is an attack where the attacker secretly intercepts and alters the communication between two parties who believe they are directly communicating with each other. Techniques include ARP spoofing, DNS spoofing, and SSL stripping. SOC analysts look for signs of session hijacking or unusual certificate warnings.',
  },
  {
    term: 'SOC (Security Operations Center)',
    description: 'A Security Operations Center (SOC) is a centralized unit within an organization that deals with security issues on an organizational and technical level. The SOC team focuses on real-time monitoring, detection, analysis, and response to cybersecurity incidents, acting as the first line of defense.',
  },
  {
    term: 'Threat Hunting',
    description: 'Threat hunting is the proactive and iterative search for malicious actors or activities that are hidden within a network and might not be detected by traditional security tools (like SIEM or EDR alerts). Hunters use hypotheses and threat intelligence to search raw data for subtle signs of compromise (TTPs).',
  },
  {
    term: 'Vulnerability',
    description: 'A vulnerability is a weakness in an information system, security procedure, internal control, or implementation that could be exploited by a threat actor to gain unauthorized access or cause harm. Vulnerability management is the process of identifying, classifying, prioritizing, and remediating these weaknesses.',
  },
  {
    term: 'Penetration Testing',
    description: 'Penetration testing (or ethical hacking) is the practice of testing a computer system, network, or web application to find security vulnerabilities that an attacker could exploit. It is a proactive security measure used to validate defenses and identify weaknesses before malicious actors do.',
  },
  {
    term: 'Social Engineering',
    description: 'Social engineering is the use of psychological manipulation to trick individuals into performing actions or divulging confidential information. Common examples include phishing, pretexting, and baiting. It exploits the human element of security, often bypassing technical controls.',
  },
  {
    term: '2FA (Two-Factor Authentication)',
    description: 'Two-Factor Authentication (2FA) is a security process in which users provide two different authentication factors to verify themselves, typically something they know (password) and something they have (a token or phone). 2FA significantly enhances account security and is a critical defense against credential theft.',
  },
  {
    term: 'Incident Response',
    description: 'Incident Response (IR) is the organized approach to addressing and managing the aftermath of a security breach or cyber attack. The goal of IR is to limit damage, reduce recovery time and costs, and learn from the incident. The process typically follows phases like Preparation, Detection & Analysis, Containment, Eradication, Recovery, and Post-Incident Activity.',
  },
  {
    term: 'Patch Management',
    description: 'Patch management is the process of distributing and applying updates to software, including security patches, to protect against vulnerabilities exploited by hackers. Timely and effective patch management is a foundational security control, often tracked by compliance frameworks like CIS.',
  },
  {
    term: 'Rootkit',
    description: 'A rootkit is a collection of malicious software tools designed to enable unauthorized access to a computer or area of its software while actively hiding its presence. Rootkits often target the operating system kernel to maintain persistence and evade detection by security software, making them highly dangerous.',
  },
  {
    term: 'Sandboxing',
    description: 'Sandboxing is a security mechanism for running programs in an isolated environment (a "sandbox") separate from the host operating system. This is used to safely execute suspicious code (e.g., email attachments or downloaded files) to analyze its behavior without risking damage to the production environment.',
  },
];