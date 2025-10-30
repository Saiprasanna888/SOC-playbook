import { TermDefinition } from "./socTermsData";

export const socProtocols: TermDefinition[] = [
  {
    term: 'TCP (Transmission Control Protocol)',
    description: 'TCP is a core protocol of the internet that provides reliable, ordered, and error-checked delivery of data between applications. It is "connection-oriented," meaning it establishes a handshake (SYN, SYN-ACK, ACK) before sending data. **SOC Relevance:** TCP logs are vital for tracking session establishment, identifying connection failures, and detecting port scanning (e.g., SYN floods).',
  },
  {
    term: 'UDP (User Datagram Protocol)',
    description: 'UDP is a simple, connectionless protocol. Unlike TCP, it does not guarantee delivery, order, or error checking, making it faster but less reliable. It is often used for services where speed is critical, like DNS, VoIP, and video streaming. **SOC Relevance:** UDP traffic is monitored for anomalies like DNS tunneling, DDoS amplification attacks (e.g., using NTP or Memcached), and unusual high-volume traffic.',
  },
  {
    term: 'IP (Internet Protocol)',
    description: 'IP is the primary protocol responsible for addressing and routing data packets across networks. It defines the structure of IP addresses (IPv4 and IPv6) and ensures packets reach their destination network. **SOC Relevance:** IP addresses are the fundamental IOCs used in almost every alert. Analysts track source and destination IPs to map the attack path and identify compromised hosts.',
  },
  {
    term: 'ICMP (Internet Control Message Protocol)',
    description: 'ICMP is used by network devices, like routers and hosts, to send error messages and operational information, most famously used by the `ping` utility to test connectivity. **SOC Relevance:** ICMP is often abused by attackers for reconnaissance (network mapping), denial-of-service attacks (ICMP floods), and covert communication (ICMP tunneling) to bypass firewalls.',
  },
  {
    term: 'ARP (Address Resolution Protocol)',
    description: 'ARP is a protocol used on local networks (LANs) to map an IP address to its corresponding physical MAC address. It is essential for devices to communicate directly within the same subnet. **SOC Relevance:** ARP is vulnerable to ARP spoofing, a Man-in-the-Middle attack where an attacker sends false ARP messages to redirect traffic through their machine. SOC analysts monitor ARP tables for unauthorized changes.',
  },
  {
    term: 'DNS (Domain Name System)',
    description: 'DNS translates human-readable domain names (like google.com) into machine-readable IP addresses. It is often called the "phonebook of the internet." **SOC Relevance:** DNS logs are critical for detecting malicious lookups, connections to known bad domains, and DNS tunneling, where attackers hide data inside DNS queries to exfiltrate it.',
  },
  {
    term: 'HTTP (Hypertext Transfer Protocol)',
    description: 'HTTP is the foundation of data communication for the World Wide Web, used to transfer web pages and other resources. It is typically unencrypted. **SOC Relevance:** HTTP traffic is monitored by proxies and WAFs for cleartext attacks, unauthorized data transfers, and connections to suspicious websites. Unencrypted HTTP is a security risk for sensitive data.',
  },
  {
    term: 'HTTPS (HTTP Secure)',
    description: 'HTTPS is the secure version of HTTP, using SSL/TLS encryption to protect data integrity and confidentiality between the user\'s browser and the web server. **SOC Relevance:** While secure, HTTPS hides malicious payloads. SOC teams often use SSL/TLS inspection (decryption) on firewalls or proxies to inspect the content for threats before re-encrypting it.',
  },
  {
    term: 'SMTP (Simple Mail Transfer Protocol)',
    description: 'SMTP is used for sending and routing email messages between mail servers. **SOC Relevance:** SMTP logs are crucial for detecting spam campaigns, high-volume outbound email (indicating a compromised account), and email spoofing attempts (where the sender address is faked).',
  },
  {
    term: 'POP3 / IMAP',
    description: 'POP3 (Post Office Protocol 3) and IMAP (Internet Message Access Protocol) are used by email clients to retrieve emails from a mail server. IMAP is generally preferred as it keeps emails on the server. **SOC Relevance:** Monitoring these protocols helps detect unusual client logins, mass email downloads (potential data theft), and the use of legacy, less secure authentication methods.',
  },
  {
    term: 'FTP (File Transfer Protocol)',
    description: 'FTP is a standard network protocol used to transfer files between a client and a server. It is inherently insecure as it transmits credentials and data in cleartext. **SOC Relevance:** FTP traffic is monitored for unauthorized file transfers, especially outbound. Due to its insecurity, its use is often restricted or replaced by secure alternatives like SFTP or FTPS.',
  },
  {
    term: 'SSH (Secure Shell)',
    description: 'SSH is a cryptographic network protocol used for operating network services securely over an unsecured network. It is primarily used for secure remote login and command-line execution. **SOC Relevance:** SSH logs are monitored for brute force attacks, unauthorized remote access, and unusual outbound SSH connections from user workstations (potential C2 tunneling).',
  },
  {
    term: 'RDP (Remote Desktop Protocol)',
    description: 'RDP is a proprietary protocol developed by Microsoft that allows a user to graphically control a remote computer. It is widely used for remote administration. **SOC Relevance:** RDP is a major target for external brute force attacks (especially port 3389). Successful RDP logins from unusual IPs or after a brute force attempt are high-priority alerts, often indicating lateral movement.',
  },
  {
    term: 'SMB (Server Message Block)',
    description: 'SMB is a network file sharing protocol used by Windows to provide shared access to files, printers, and serial ports. It is critical for Active Directory and Windows networking. **SOC Relevance:** SMB is heavily monitored for lateral movement (e.g., PsExec using SMB), ransomware spread across network shares, and unauthorized outbound SMB traffic (which should almost never happen).',
  },
  {
    term: 'LDAP (Lightweight Directory Access Protocol)',
    description: 'LDAP is an application protocol used for accessing and maintaining distributed directory information services, such as Active Directory. It is fundamental for authentication and authorization in Windows environments. **SOC Relevance:** LDAP traffic is monitored for enumeration attempts (reconnaissance), unauthorized queries, and attacks like LDAP injection or Kerberoasting, which target directory services.',
  },
  {
    term: 'Kerberos',
    description: 'Kerberos is a network authentication protocol that uses secret-key cryptography to verify the identity of users and services in a non-secure network, most notably used by Active Directory. It relies on tickets (TGT and ST) for authentication. **SOC Relevance:** Kerberos logs are critical for detecting Golden Ticket and Silver Ticket attacks, which involve forging these tickets to gain unauthorized domain access.',
  },
  {
    term: 'SNMP (Simple Network Management Protocol)',
    description: 'SNMP is used for monitoring and managing network devices (routers, switches, servers). It allows administrators to collect information and modify device configurations remotely. **SOC Relevance:** SNMP is often targeted because older versions (v1/v2) use cleartext "community strings" (passwords). Compromised SNMP can lead to network reconnaissance or device misconfiguration.',
  },
  {
    term: 'Syslog',
    description: 'Syslog is a standard protocol used to send system and security messages (logs) from various devices (firewalls, servers, applications) to a central collector, typically the SIEM. **SOC Relevance:** Syslog is the backbone of log collection. SOC teams monitor Syslog health to ensure no log sources fail, which would create a critical security blind spot.',
  },
  {
    term: 'BGP (Border Gateway Protocol)',
    description: 'BGP is the routing protocol that manages how data packets are routed across the internet between large autonomous systems (AS). It determines the most efficient path for traffic. **SOC Relevance:** BGP hijacking is a critical external threat where an attacker falsely advertises ownership of IP ranges, redirecting traffic (including sensitive data) through their network. Threat intelligence monitors BGP announcements.',
  },
  {
    term: 'SIP (Session Initiation Protocol)',
    description: 'SIP is a signaling protocol used for initiating, maintaining, and terminating real-time communication sessions, including Voice over IP (VoIP) calls and video conferencing. **SOC Relevance:** SIP traffic is monitored for denial-of-service attacks (SIP floods), toll fraud, and unauthorized eavesdropping on communication channels.',
  },
  {
    term: 'DHCP (Dynamic Host Configuration Protocol)',
    description: 'DHCP automatically assigns IP addresses and other network configuration parameters to devices on a network. **SOC Relevance:** DHCP logs are essential for linking a temporary IP address to a specific device (MAC address) at the time of an incident. SOC teams also monitor for rogue DHCP servers attempting to redirect network traffic.',
  },
  {
    term: 'NTP (Network Time Protocol)',
    description: 'NTP is used to synchronize the clocks of computer systems over a network. Accurate time synchronization is crucial for log correlation and authentication protocols like Kerberos. **SOC Relevance:** Time drift on critical servers can disrupt security tools. NTP is also sometimes exploited in DDoS amplification attacks.',
  },
];