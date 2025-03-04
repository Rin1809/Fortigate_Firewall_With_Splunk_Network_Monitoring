# Design And Deployment Business Nework Support By Fortigate Firewall And Splunk Network Monitoring  

**Lab Report: Network Design and Implementation for a Small Business**


**1. Preparation**

![image](https://github.com/user-attachments/assets/2db41843-e134-42ba-8ab2-50a2f3690680)
(Foritgate Firewall Dashboard)

**2. Design and Implement a Computer Network for a Small Business.** This network needs to meet the following requirements:

*   **Internet Connection:** The network must be connected to the Internet through a firewall. The public IP address of the firewall is 192.168.19.x.
*   **DMZ:** A DMZ is required to host a public web server. This web server will have the IP address 192.168.40.254/24.
*   **LAN:** The internal LAN network needs to support Active Directory services (including DHCP, DNS, and FTP), network security monitoring, and user authentication. The IP address range for the LAN is 192.168.30.0/24. The Active Directory server will have the IP address 192.168.30.100/24, and the Splunk server (network security monitoring) will have the IP address 192.168.30.21/24. LAN clients will receive dynamic IP addresses via DHCP from the AD server.
*   **Firewall:** The firewall must be configured to protect the network from external threats. It needs to support IDS/IPS, VPN, and firewall backup for redundancy. The firewall will have the IP address 192.168.19.x/24 for the WAN connection, 192.168.40.1/24 for the DMZ connection, and 192.168.30.1/24 for the LAN connection.
*   **Remote Access:** Administrators need to be able to remotely access the LAN network via VPN (using IPsec) for SSH and RDP.

**Tasks:**

1.  Draw a network diagram clearly showing all components, connections, and IP addresses. *(Completed - see diagram below)*
2.  Detail the firewall configuration, including security policies, IDS/IPS, and VPN. *(Detailed in Section II.2)*
3.  Explain the Active Directory configuration, including DHCP, DNS, and FTP. *(Detailed in Section III)*
4.  Describe how administrators can securely connect to the LAN remotely, summarized in steps including SSH and Remote Desktop. *(Detailed in Section II.3 & III.1.3)*
5.  Configure network security monitoring for the LAN and DMZ. *(Detailed in Section III.3)*

**2. Network Diagram**

![image](https://github.com/user-attachments/assets/e12f2336-e039-404a-8ff9-c9006080eded)

**(Explanation of the Network Diagram):**

The network diagram visually represents the small business network architecture. Key components include:

*   **Internet:**  Simulates the external network.
*   **FortiGate Firewall:** The central security appliance, segmenting the network and enforcing security policies.
*   **WAN Zone:** The external interface of the firewall connected to the Internet (192.168.19.x network).
*   **DMZ Zone:** Hosts the public-facing Web Server (192.168.40.0/24 network), isolated for security.
*   **LAN Zone:** The internal trusted network (192.168.30.0/24 network) containing:
    *   **AD Server:** Provides Active Directory, DHCP, and DNS services.
    *   **Splunk Server:** For network security monitoring and log analysis.
    *   **LAN Client:** Represents typical employee workstations.
*   **Admin PC:** Located externally, simulating remote administrator access via VPN.

**3. Information**

| Device          | Zone        | IP Address        | Notes                                                                                                                                 |
| --------------- | ----------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Admin PC        | External    | N/A               | Connects to LAN via VPN for secure remote administration.                                                                                     |
| Internet        | External    | 192.168.19.2      | Simulates the internet connection, connected to the Firewall's WAN interface.                                                                  |
| Firewall (WAN)  | WAN         | 192.168.19.x/24   | WAN interface of the FortiGate, connecting to the Internet and routing traffic to DMZ and LAN.                                             |
| Firewall (LAN)  | LAN         | 192.168.30.1/24   | LAN interface of the FortiGate, acting as the gateway for the internal LAN network.                                                             |
| DMZ Server      | DMZ         | 192.168.40.254/24 | Hosts the public-facing Web Server, accessible from the Internet and LAN.                                                                     |
| Splunk Server   | LAN         | 192.168.30.21/24  | Network Security Monitoring server, collecting logs from FortiGate, Web Server, and AD Server.                                            |
| AD Server       | LAN         | 192.168.30.100/24 | Active Directory Domain Controller, providing DHCP, DNS, FTP, and User Authentication services for the LAN network.                             |
| LAN Client      | LAN         | DHCP              | Represents typical employee workstations, receiving dynamic IP addresses from the AD Server via DHCP.                                          |
| Existing Websites | N/A       | www.goodshopping.com, www.moviescope.com | Example websites used for testing firewall rules, DNS resolution, and web server accessibility from different network zones. |

**3. Functions/Services**

| Zone        | Function/Service                                                                    | Notes                                                                                                                                                               |
| ----------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LAN         | - Active Directory (DHCP, DNS, FTP) - Policies - Network Security Monitoring - User Authentication | Main internal network for employees and internal devices, providing core network services, security monitoring, user access control, and centralized management. |
| DMZ         | - Web Server                                                                          | Hosts public-facing web applications, isolated from the internal LAN to minimize security risks and potential lateral movement in case of compromise.           |
| Firewall    | - Rules - IDS/IPS - VPN - Backup Firewall                                             | Acts as a security gateway, located between the Internet and internal networks (LAN, DMZ), enforcing security policies, intrusion detection/prevention, and VPN access. |
| Admin PC (Internet) | - SSH - RDP - VPN (IPsec)                                                         | Simulates remote administrator access, enabling secure SSH and Remote Desktop access to the LAN network via a secure IPsec VPN tunnel for management tasks.        |

**II. FortiGate Firewall Setup**

This section details the configuration steps performed on the FortiGate firewall to implement the required security policies and network segmentation.

**1. Firewall Information**

This section summarizes the basic interface configuration of the FortiGate firewall, setting up the physical ports and assigning IP addresses for each network zone.

*   Port 1 = WAN
*   Port 2 = LAN
*   Port 3 = DMZ

| Port  | Mode   | IPv4 Address      |
| ----- | ------ | ----------------- |
| port1 | DHCP   | 192.168.19.162    |
| port2 | Static | 192.168.30.1      |
| port3 | Static | 192.168.40.1      |

![image](https://github.com/user-attachments/assets/e38e8dc0-d9ee-4ffc-a9b6-5abda6098890)

**(Explanation of Firewall Interface Configuration):**

*   **Port 1 (WAN):** Configured in DHCP mode to automatically obtain an IP address from the simulated Internet network (192.168.19.0/24 network).  It receives the IP address 192.168.19.162 in this example.  This simulates a typical WAN connection where the firewall obtains its public IP dynamically from an ISP.
*   **Port 2 (LAN):** Configured with a static IP address of 192.168.30.1/24. This IP address serves as the gateway for the LAN network (192.168.30.0/24 network). Static IP is used for the LAN interface for consistent internal routing.
*   **Port 3 (DMZ):** Configured with a static IP address of 192.168.40.1/24. This IP address serves as the gateway for the DMZ network (192.168.40.0/24 network). Static IP is used for the DMZ interface for consistent public server access.

**2. Firewall Rules**

This section details the firewall rules created on the FortiGate to control traffic flow between different network zones (LAN, DMZ, WAN) and implement security policies.

**2.1. Rules for LAN**

These rules govern traffic originating from the LAN zone.

*   **Allow LAN access to WEB (Internal DMZ web access only, block public Internet web access) | Allow Ping for connection testing.**
    *   Ports: 443, 80, 53, ICMP/8

![image](https://github.com/user-attachments/assets/76f576b0-89fa-48cb-b4bf-bb2955f5cd79)
![image](https://github.com/user-attachments/assets/58c1f0b1-5cf3-4d39-bfb5-cf0b2fdb049c)

**(Explanation of LAN to DMZ Web Access Rule):**

*   **Name:**  A descriptive name like "LAN\_to\_DMZ\_WEB\_Access" is used for rule identification.
*   **Action:** "ACCEPT" -  Allows traffic matching the rule criteria.
*   **Source Interface:** "port2" (LAN) -  Traffic originates from the LAN interface.
*   **Destination Interface:** "port3" (DMZ) - Traffic is destined for the DMZ interface.
*   **Source Address:** "ALL" -  Applies to traffic from all IP addresses within the LAN zone.
*   **Destination Address:** "DMZ\_Servers" -  Likely an address object or group created to represent the DMZ Web Server (192.168.40.254). This limits the destination to the specific web server in the DMZ.
*   **Schedule:** "always" - Rule is always active.
*   **Service:** "WEB\_Access" -  Likely a service object or group containing ports 443 (HTTPS), 80 (HTTP), and 53 (DNS), and ICMP/8 (Ping). This allows web browsing, DNS resolution, and ping for testing to the DMZ web server from the LAN.
*   **Log Allowed Traffic:** Enabled for monitoring and auditing purposes.

**(Rationale):** This rule allows users on the LAN to access the web server in the DMZ (for internal testing or administration) but restricts general internet web access from the LAN, enhancing internal network security by limiting outbound web browsing to only necessary internal resources.

*   **Open VPN to LAN network for administrators with services like SSH, RDP, PING, IKE (VPN tunnel). | Allow Ping for connection testing.**
    *   Ports: 500, 4500, 3389, 22, ICMP/8

![image](https://github.com/user-attachments/assets/f583a539-8380-4465-a62a-e264d42c21d1)

**(Explanation of VPN to LAN Access Rule):**

*   **Name:**  A descriptive name like "VPN\_to\_LAN\_Admin\_Access" is used for rule identification.
*   **Action:** "ACCEPT" - Allows VPN traffic to access the LAN network.
*   **Source Interface:** "VPN" -  Traffic originates from the VPN tunnel interface (representing remote VPN clients).
*   **Destination Interface:** "port2" (LAN) - Traffic is destined for the LAN interface.
*   **Source Address:** "ALL" - Applies to traffic from all VPN client IP addresses within the VPN IP range.
*   **Destination Address:** "LAN\_NET" -  Represents the entire LAN network (192.168.30.0/24 network). This allows VPN users to access all devices on the LAN.
*   **Schedule:** "always" - Rule is always active when VPN is connected.
*   **Service:** "ADMIN\_VPN\_Access" - Likely a service object or group containing ports 500, 4500 (IPsec VPN), 3389 (RDP), 22 (SSH), and ICMP/8 (Ping). This allows VPN users to establish IPsec VPN tunnels and access LAN resources using RDP, SSH, and ping for management and troubleshooting.
*   **Log Allowed Traffic:** Enabled for monitoring and auditing VPN access.

**(Rationale):** This rule enables secure remote administration access to the LAN network via IPsec VPN for authorized administrators. It allows necessary management protocols (SSH, RDP, Ping) and VPN tunnel establishment (IKE, IPsec NAT-T) while restricting general access from the internet to the LAN directly.

**2.1. Rules for DMZ**

These rules govern traffic originating from the DMZ zone.

*   **Open port for the DMZ zone to only send logs to the Splunk server in the LAN for network security monitoring.**
    *   Port: 9997

![image](https://github.com/user-attachments/assets/b7d70a72-fc7d-4e3a-8f7b-053aadc1d42a)

**(Explanation of DMZ to Splunk Logging Rule):**

*   **Name:**  A descriptive name like "DMZ\_to\_Splunk\_Logging" is used for rule identification.
*   **Action:** "ACCEPT" - Allows traffic for log forwarding.
*   **Source Interface:** "port3" (DMZ) - Traffic originates from the DMZ interface.
*   **Destination Interface:** "port2" (LAN) - Traffic is destined for the LAN interface.
*   **Source Address:** "ALL" - Applies to traffic from all IP addresses within the DMZ zone.
*   **Destination Address:** "Splunk\_Server" - Likely an address object or group created to represent the Splunk Server (192.168.30.21). This limits the destination to the Splunk server in the LAN.
*   **Schedule:** "always" - Rule is always active for continuous logging.
*   **Service:** "Splunk\_Port" - Likely a service object or group containing port 9997 (Splunk's default port for receiving logs). This allows the DMZ server to send logs to the Splunk server on port 9997.
*   **Log Allowed Traffic:** Enabled for monitoring and auditing log forwarding traffic.

**(Rationale):** This rule allows the web server in the DMZ to send logs to the Splunk server in the LAN for centralized network security monitoring. It restricts DMZ outbound traffic to the LAN to only the necessary port for logging, adhering to the principle of least privilege and enhancing security by limiting DMZ outbound communication.

**2.2. Rules for WAN**

These rules govern traffic originating from the WAN zone (Internet).

*   **Open port for users outside the internet to access the web server in the DMZ. And ping for testing.**
    *   Ports: 443, 80, 53, ICMP/8

![image](https://github.com/user-attachments/assets/9eef9944-92f2-40b5-adb7-68b314ffc929)

**(Explanation of WAN to DMZ Web Access Rule):**

*   **Name:**  A descriptive name like "WAN\_to\_DMZ\_WEB\_Access" is used for rule identification.
*   **Action:** "ACCEPT" - Allows internet users to access the web server.
*   **Source Interface:** "port1" (WAN) - Traffic originates from the WAN interface (Internet).
*   **Destination Interface:** "port3" (DMZ) - Traffic is destined for the DMZ interface.
*   **Source Address:** "ALL" - Applies to traffic from all IP addresses on the internet (any external IP).
*   **Destination Address:** "DMZ\_Server" -  Likely an address object or group representing the DMZ Web Server (192.168.40.254). This directs traffic to the specific web server in the DMZ.
*   **Schedule:** "always" - Rule is always active for continuous web server accessibility.
*   **Service:** "WEB\_Access" -  Likely a service object or group containing ports 443 (HTTPS), 80 (HTTP), 53 (DNS), and ICMP/8 (Ping). This allows external users to access the web server on ports 80 and 443, and allows DNS and ping for testing and accessibility.
*   **Log Allowed Traffic:** Enabled for monitoring and auditing web access from the internet.

**(Rationale):** This rule allows legitimate internet traffic to reach the public web server in the DMZ, enabling public access to the website hosted on the DMZ server. It opens ports 80 and 443 for web access and port 53 and ICMP for testing, while blocking other unsolicited inbound traffic from the internet, protecting the internal network.

**3. VPN Tunnel**

This section details the IPsec VPN configuration for secure remote administrator access to the LAN network.

Video :
https://github.com/user-attachments/assets/2deea068-4efb-4cbf-a606-4337e739b100

Configure VPN for administrator remote access to the LAN network.

*   **VPN Group:** named "ado-group" containing VPN members (ado).

![image](https://github.com/user-attachments/assets/e82c3f05-6e22-4048-9a5c-cdd29c5727cd)

**(Explanation of VPN Group Creation):**

*   **Group Name:** "ado-group" -  A descriptive name for the VPN user group is created for easy management of VPN users.
*   **Members:** The group contains VPN users, in this case, "ado".  Users are added to this group to grant them VPN access.

**(Rationale):** Creating a VPN group allows for centralized management of VPN user accounts and permissions. Instead of configuring VPN access for each user individually, you can manage access at the group level, simplifying administration and ensuring consistent VPN access policies.

*   **VPN Tunnel:** named "Ado-VPN", type Remote Access.
*   ![image](https://github.com/user-attachments/assets/b4d4cba3-c383-442f-b964-56b06005b2ba)

    *   Incoming interface: WAN port.
    *   Pre-shared key: 12345678.
    *   Authorization: ado-group.
    *   ![image](https://github.com/user-attachments/assets/18bfbb3f-68f6-4fc3-ac9a-4a2b05df653d)

    *   Local interface: LAN.
    *   VPN IP range to assign: 1.1.1.1-1.1.1.5/32.
    *   ![image](https://github.com/user-attachments/assets/c6aea50e-65ce-4242-80c6-4791e9162e1a)

**(Explanation of IPsec VPN Configuration):**

*   **VPN Name:** "Ado-VPN" - A descriptive name for the VPN tunnel for easy identification.
*   **Type:** "Remote Access" - Configures an IPsec VPN for remote access, allowing individual users (administrators) to connect to the LAN from external networks.
*   **Incoming Interface:** "WAN port (port1)" - VPN connections will be accepted on the FortiGate's WAN interface (port1), making the VPN accessible from the internet.
*   **Pre-shared Key:** "12345678" - A pre-shared key is configured for IPsec IKE authentication. **Security Note:** In a real-world scenario, a stronger, more complex pre-shared key should be used, or certificate-based authentication should be implemented for enhanced security.
*   **Authorization:** "ado-group" -  The "ado-group" (created in the previous step) is selected for authorization. Only users belonging to this group will be allowed to authenticate and establish VPN connections.
*   **Local Interface:** "LAN" -  Specifies that VPN users will be granted access to the LAN network (192.168.30.0/24 network) once the VPN tunnel is established.
*   **VPN IP Range to Assign:** "1.1.1.1-1.1.1.5/32" - A private IP address range (1.1.1.1 to 1.1.1.5) is defined for assigning to VPN clients.  Each VPN client connecting will be assigned an IP address from this range.  The /32 subnet mask indicates that each IP address is assigned individually.

We will have
![image](https://github.com/user-attachments/assets/e0a5bdb3-143c-4b1e-87e2-d638e7d43db6)

**(Summary of VPN Configuration):**

The IPsec VPN is configured to allow remote administrators (members of the "ado-group") to securely connect to the LAN network through the FortiGate firewall's WAN interface. VPN users will authenticate using the pre-shared key and their user credentials (members of "ado-group") and will be assigned IP addresses from the 1.1.1.1-1.1.1.5/32 range.  Once connected, they will have secure access to the LAN network for remote administration tasks.

**4. IPS / IDS**

This section describes the configuration of Intrusion Prevention System (IPS) and Intrusion Detection System (IDS) features on the FortiGate firewall to enhance network security by monitoring and preventing malicious traffic.

Video 1:

https://github.com/user-attachments/assets/2cd79535-d518-457f-a3c1-089f0c92359e

Video 2:

https://github.com/user-attachments/assets/0584c5bf-fb2b-490b-8c10-0f339aa6d36c

Video 3:

https://github.com/user-attachments/assets/1d5ac8d7-5b22-4b1d-b342-4e90ec5164ed

Video 4:

https://github.com/user-attachments/assets/a6f7acbb-2282-4ad6-a9a3-6d931c342088

Monitor and prevent attacks with IPS and IDS from external networks (WAN) and internal networks (LAN) to the Server (DMZ).
![image](https://github.com/user-attachments/assets/4e64e6de-7e8e-4322-877b-2bc9ccd1d878)
![image](https://github.com/user-attachments/assets/03933ea4-658f-4e1a-ac37-334014294f11)
![image](https://github.com/user-attachments/assets/d622e67a-b422-4f8d-8815-f42043694bb0)

**(Explanation of IPS/IDS Configuration):**

*   **Enable IPS/IDS on Firewall Policies:** IPS/IDS is enabled on the firewall policies that control traffic to and from the DMZ zone.  This typically involves enabling IPS/IDS profiles on the WAN to DMZ and LAN to DMZ firewall rules to inspect traffic destined for the web server in the DMZ.
*   **IPS Profiles:**  IPS profiles are configured to define the level of intrusion prevention and detection.  These profiles contain signatures and rules to detect and prevent various types of network attacks.
*   **WAF (Web Application Firewall):**  A Web Application Firewall (WAF) is implemented to protect the web server in the DMZ from web-specific attacks such as XSS (Cross-Site Scripting) and SQL Injection.  The WAF acts as an IDS/IPS layer specifically for web application traffic.
*   **WAF Actions:** The WAF is configured to:
    *   **Alert warnings for XSS attacks:**  Detect and log XSS attacks, generating alerts to notify administrators of potential XSS attempts.
    *   **Block SQL Injection attacks:** Detect and actively block SQL Injection attacks, preventing attackers from exploiting SQL injection vulnerabilities to compromise the web server and database.

![image](https://github.com/user-attachments/assets/55b26fd4-33dc-4baf-a2ee-1f98bdd2a469)

**(Rationale):** Implementing IPS/IDS and WAF enhances the security of the network, particularly for the public-facing web server in the DMZ.  IPS/IDS provides network-level threat detection and prevention, while the WAF provides application-layer protection against web-specific attacks, creating a layered security approach.  The configuration focuses on both detecting (IDS - alerts for XSS) and preventing (IPS/WAF - blocking SQL Injection) attacks.

**5. Firewall Backup Rule**

This section describes how to create a backup of the FortiGate firewall configuration for redundancy and disaster recovery purposes.

Video 1:
https://github.com/user-attachments/assets/2c34a9c1-0a8c-40b7-bfa0-322debfa11d2

Video 2:
https://github.com/user-attachments/assets/f66755f8-bcff-41aa-9163-9e1ba3af5e7f

*   Download the backup file after completing firewall setup for redundancy during Restore.
*   ![image](https://github.com/user-attachments/assets/739e72fa-5d52-4c5b-bb2f-ad9bf4cdf63d)

**(Explanation of Firewall Backup Download):**

*   **Backup Download:** After configuring the FortiGate firewall, a backup of the configuration is downloaded from the FortiGate web interface.  This backup file contains the complete firewall configuration, including firewall rules, VPN settings, IPS/IDS profiles, and other configurations.
*   **Purpose:** Downloading a firewall backup is crucial for:
    *   **Redundancy and Disaster Recovery:**  The backup file can be used to quickly restore the firewall configuration in case of hardware failure, configuration corruption, or other disasters.
    *   **Configuration Management:**  Backup files serve as snapshots of the firewall configuration at specific points in time, allowing for version control and rollback to previous configurations if needed.

*   Encrypt the backup file for security.
*   ![image](https://github.com/user-attachments/assets/25b5339f-52b5-4b10-ac22-20765dc2124d)

**(Explanation of Backup Encryption):**

*   **Backup Encryption:**  When downloading the backup file, the option to encrypt the backup file is selected.  This encrypts the configuration backup using a user-defined password.
*   **Security Benefit:** Encrypting the backup file protects sensitive information contained within the configuration (such as passwords, pre-shared keys, and other security settings) from unauthorized access if the backup file is compromised or falls into the wrong hands.  Encryption adds a layer of security to the backup.

*   Save the Firewall Backup File to be used for Restore.
*   ![image](https://github.com/user-attachments/assets/158bbc50-b3c2-42cb-8b61-88a61de02706)

**(Explanation of Backup File Storage):**

*   **Secure Storage:** The encrypted firewall backup file is saved to a secure location for safekeeping.  This location should be separate from the firewall itself and ideally offsite to ensure backup availability even in case of physical damage to the firewall or the primary network location.
*   **Restore Purpose:**  This backup file will be used to restore the FortiGate firewall configuration if needed, ensuring business continuity and minimizing downtime in case of firewall failure or configuration issues.

**III. LAN Setup**

This section details the configuration of services and policies within the LAN network, primarily focused on the Active Directory server and user access management.

**1. (AD, DHCP, DNS, FTP) Server**

This section describes the configuration of the Active Directory server to provide core network services for the LAN, including DHCP, DNS, FTP, and user authentication.

**1.1. DHCP Server**

Video :
https://github.com/user-attachments/assets/5a310915-b56c-4413-aeb1-69749382d07b

*   Create a DHCP Scope for the LAN network named "LAN".
*   ![image](https://github.com/user-attachments/assets/1c9999ca-6841-4b4c-b8dc-deda3f8ca735)

**(Explanation of DHCP Scope Creation):**

*   **DHCP Scope Name:** "LAN" - A descriptive name "LAN" is assigned to the DHCP scope for easy identification, reflecting that this scope is for the LAN network.
*   **Purpose:** Creating a DHCP scope on the AD server enables dynamic IP address assignment for devices on the LAN network, simplifying IP address management and reducing manual configuration.

*   IP address range for this scope to assign: 192.168.30.20 - 192.168.30.254/24.
*   ![image](https://github.com/user-attachments/assets/bf85ce8d-040d-4713-9611-253d55f80377)

**(Explanation of DHCP IP Address Range):**

*   **IP Address Range:** 192.168.30.20 - 192.168.30.254/24 - This defines the range of IP addresses that the DHCP server will assign dynamically to LAN clients.  The range starts from 192.168.30.20 and goes up to 192.168.30.254 within the 192.168.30.0/24 network.
*   **Rationale:** This range provides a pool of IP addresses for dynamic assignment, excluding the first few IP addresses in the 192.168.30.0/24 subnet, which are typically reserved for static assignments (like the firewall LAN interface and the AD server itself).

*   No special IP ranges excluded by DHCP.
*   ![image](https://github.com/user-attachments/assets/695065fa-dbd7-4ccb-a98f-1729fcf8262f)

**(Explanation of DHCP Exclusions):**

*   **No Exclusions:**  No IP address ranges are explicitly excluded from the DHCP scope in this configuration.  This means that the DHCP server is allowed to assign any IP address within the defined range (192.168.30.20 - 192.168.30.254).
*   **Rationale:** In simpler network setups, exclusions might not be necessary. However, in more complex networks, you might define exclusions to reserve specific IP addresses within the DHCP range for static assignments or other purposes.

*   Gateway assigned by this DHCP Scope is the Firewall IP for Firewall management.
*   ![image](https://github.com/user-attachments/assets/6372ed97-9bb1-4644-9bb5-7b454d5fa932)

**(Explanation of DHCP Gateway Setting):**

*   **Gateway:** 192.168.30.1 - The Gateway option in the DHCP scope is set to 192.168.30.1, which is the IP address of the FortiGate firewall's LAN interface.
*   **Rationale:**  Setting the Gateway in the DHCP scope is essential for enabling internet access for LAN clients. The gateway IP address tells LAN clients where to send traffic destined for networks outside the LAN (including the internet).  By setting the firewall's LAN IP as the gateway, LAN clients will route their internet-bound traffic through the FortiGate firewall for security inspection and routing to the WAN.

Total
![image](https://github.com/user-attachments/assets/9edef7dc-c0c2-4e59-af07-19670463d89a)

**(Summary of DHCP Server Configuration):**

The DHCP server on the AD server is configured to dynamically assign IP addresses to LAN clients within the 192.168.30.0/24 network, using the range 192.168.30.20 - 192.168.30.254. The DHCP scope is configured to provide the FortiGate firewall's LAN interface IP address (192.168.30.1) as the default gateway, ensuring that LAN clients route their internet traffic through the firewall.

**1.2. User Authentication**

This section describes the creation of user accounts and groups in Active Directory for user authentication and access control on the LAN network.

Video :
https://github.com/user-attachments/assets/b8cc4a4c-2a57-4fb7-bfb5-1521e0bb9823

*   **User and Group List:**
    *   Users: Sofieru, Ado9, suisei  ---> in "quantri" (admin) group.
    *   Users: nhansu1, nhansu2, nhansu3 ---> in "nhansu" (HR) group.
    *   Users: ketoan1, ketoan2, ketoan3 —> in "ketoan" (accounting) group.

*   **Groups:**
*   ![image](https://github.com/user-attachments/assets/edb7e1dc-9bb2-4aab-9b09-0f71db2d9c4a)

    *   quantri (admin) Group
    *   ![image](https://github.com/user-attachments/assets/e895c077-8424-4d87-a350-2cfff86b0ded)

    *   nhansu (HR) Group
    *   ![image](https://github.com/user-attachments/assets/584ec06a-f0bc-4591-bfc6-18cdb3b84f23)

    *   ketoan (accounting) Group
    *   ![image](https://github.com/user-attachments/assets/7c8a7888-844a-40a5-8b0e-675f9b7a72e7)

**(Explanation of User and Group Creation in Active Directory):**

*   **User Accounts:**  Multiple user accounts are created in Active Directory, representing employees in different departments:
    *   **Admin Users:** "Sofieru," "Ado9," and "suisei" are created for administrators, intended to have elevated privileges.
    *   **HR Users:** "nhansu1," "nhansu2," and "nhansu3" are created for employees in the Human Resources (HR) department.
    *   **Accounting Users:** "ketoan1," "ketoan2," and "ketoan3" are created for employees in the Accounting department.
*   **Group Accounts:** Three groups are created in Active Directory to organize users based on their roles and departments:
    *   **quantri (admin) Group:** For administrator users, granting them administrative privileges.
    *   **nhansu (HR) Group:** For Human Resources department users, granting them access to HR-related resources.
    *   **ketoan (accounting) Group:** For Accounting department users, granting them access to accounting-related resources.
*   **User Group Membership:**  Users are added to their respective groups (e.g., "Sofieru," "Ado9," "suisei" are added to the "quantri" group).

**(Rationale):** Creating user accounts and groups in Active Directory is fundamental for centralized user management and authentication on the LAN network. This allows for:

*   **User Authentication:**  Users can authenticate to the domain using their Active Directory credentials to access network resources and services.
*   **Access Control:**  Groups are used to implement Role-Based Access Control (RBAC), allowing administrators to assign permissions and access rights to groups rather than individual users, simplifying access management.
*   **Policy Enforcement:**  Group Policy Objects (GPOs) can be linked to OUs (Organizational Units) containing these groups to enforce security policies and configurations consistently across users within specific departments or roles (as demonstrated in section III.2).

*   Successful Domain login with the users created.

**(Verification of Domain Login):**

The report indicates that domain logins with the created users are successful.  This means that LAN clients joined to the Active Directory domain can successfully authenticate using the newly created user accounts (e.g., "ketoan3" successfully logging in).  Successful domain login confirms that Active Directory user authentication is working correctly.

**1.3. User Permissions**

This section details the configuration of file share permissions on the Active Directory server to control user access to shared folders and files based on their group membership and individual user accounts.

Video 1:
https://github.com/user-attachments/assets/fd0eb1cb-b53f-4864-a353-707ac5785570

Video 2:
https://github.com/user-attachments/assets/1e6a02a8-1a86-4de5-bd07-a14243876dfe

Video 3:
https://github.com/user-attachments/assets/661dd3f4-f38b-4c64-a6e1-bf37fc1b3178

*   **Data:** "Ado-Congviec" (Ado-Work) shared folder.
*   **Data Access Permissions List:**
    *   Group: quantri (admin) —> Full control (modify permissions).
    *   Group: nhansu (HR) —> "nhansu" (HR) subfolder access.
    *   Group: ketoan (accounting) —> "ketoan" (accounting) subfolder access.
    *   User: ketoan1 —> //ketoan/ketoan1 (read/write/execute/remove).
    *   User: ketoan2 —> //ketoan/ketoan2 (read/write/execute/remove).
    *   User: ketoan3 —> //ketoan/ketoan3 (read/write/execute/remove).
    *   User: nhansu1 —> //nhansu/nhansu1 (read/write/execute/remove).
    *   User: nhansu2 —> //nhansu/nhansu2 (read/write/execute/remove).
    *   User: nhansu3 —> //nhansu/nhansu3 (read/write/execute/remove).
    *   Group: quantri (admin) —> Full control.
![image](https://github.com/user-attachments/assets/776b4968-d2a6-447f-9ceb-759960116045)
![image](https://github.com/user-attachments/assets/48bfb41d-67fa-4187-8ad4-12a7dbb88fce)
![image](https://github.com/user-attachments/assets/f61f53cd-a96f-4494-81bc-9510c6187639)

**(Explanation of File Share Permissions Configuration):**

*   **Shared Folder:** "Ado-Congviec" (Ado-Work) - A shared folder named "Ado-Congviec" is created on the AD server to host shared work files.
*   **Permissions Structure:** A hierarchical permission structure is implemented on the "Ado-Congviec" share:
    *   **"Ado-Congviec" (Root Folder):**
        *   **"quantri" (admin) Group:** "Full Control" permissions are granted, giving administrators full access to all files and subfolders within the share, including the ability to modify permissions.
        *   **"nhansu" (HR) and "ketoan" (accounting) Groups:** "Read-Only" permissions are granted to the root folder. This allows members of these groups to browse the share and access content within their respective subfolders but prevents them from modifying or deleting files at the root level or in other department's subfolders.
    *   **Department Subfolders ("nhansu," "ketoan"):** Subfolders named "nhansu" (HR) and "ketoan" (accounting) are created within the "Ado-Congviec" share, representing departmental folders.
        *   **"nhansu" (HR) Subfolder:** Access is primarily controlled through user-level permissions within subfolders (see below).  Group-level read-only access is inherited from the root folder.
        *   **"ketoan" (accounting) Subfolder:** Access is primarily controlled through user-level permissions within subfolders (see below). Group-level read-only access is inherited from the root folder.
    *   **User Subfolders (e.g., "nhansu1," "ketoan1"):**  Individual user subfolders are created within each department subfolder (e.g., "//nhansu/nhansu1", "//ketoan/ketoan1").
        *   **Individual User Folders:**  For each user within the "nhansu" and "ketoan" groups, specific user subfolders are created within their department folder (e.g., "nhansu1" folder for "nhansu1" user).
        *   **User-Specific Permissions:**  Each user is granted "Read/Write/Execute/Remove" permissions to *their own* subfolder (e.g., "ketoan1" user gets full control over the "//ketoan/ketoan1" folder).  This allows users to fully manage files within their personal work folders.
*   **Mapping Drive Z:** The "Ado-Congviec" file share is mapped to drive letter Z: for users on the LAN. This makes the shared folder easily accessible to users through Windows Explorer.

*   Share the "Ado-Congviec" (Ado-Work) file share for the groups.
*   ![image](https://github.com/user-attachments/assets/9a4e8808-8f5a-45e5-8e19-c347d8bab569)
*   ![image](https://github.com/user-attachments/assets/f23812b6-1872-445f-b1b9-7231910e5e6f)

**(Explanation of File Share Sharing):**

The "Ado-Congviec" folder is shared using Windows File Sharing (SMB/CIFS) to make it accessible over the network.  File sharing is enabled for the created share.

*   Map the work file drive to drive Z: for Users (similar for other Users).
*   ![image](https://github.com/user-attachments/assets/1e9a4264-d3a0-4b3f-ac02-97c2509b42b6)

**(Explanation of Drive Mapping):**

Drive letter Z: is mapped to the "\\AD-Server\Ado-Congviec" network path for users.  Drive mapping provides easy user access to the shared folder.

*   Full control for "quantri" (admin) group on the master "Ado-Congviec" folder.
*   ![image](https://github.com/user-attachments/assets/5b617e7a-80fc-40be-998e-d0b4c85cc8da)
*   ![image](https://github.com/user-attachments/assets/ed9983da-045e-42bd-b0cf-dde957845bbb)

**(Explanation of "quantri" (admin) Group Permissions):**

The "quantri" (admin) group is granted "Full Control" permissions on the root "Ado-Congviec" folder.  Admin group has full control over the root share.

*   Read-only permission for "nhansu" (HR) and "ketoan" (accounting) groups on the master "Ado-Congviec" folder.
*   ![image](https://github.com/user-attachments/assets/3ce06f7b-27c3-459f-a584-39c21f0ae749)
*   ![image](https://github.com/user-attachments/assets/d5c0d734-a901-427f-95ad-6355ac7da396)

**(Explanation of "nhansu" (HR) and "ketoan" (accounting) Group Permissions on Root Folder):**

The "nhansu" (HR) and "ketoan" (accounting) groups are granted "Read-Only" permissions on the root "Ado-Congviec" folder.  HR and Accounting groups have read-only access to the root share.

*   "ketoan" subfolder access only for "ketoan" (accounting) and "quantri" (admin) groups (similar for "nhansu" subfolder).
*   ![image](https://github.com/user-attachments/assets/438a4b55-23d9-4205-8d7d-6ccf972d73fd)
*   ![image](https://github.com/user-attachments/assets/b987080f-502d-4e60-bc43-b526cab725c2)

**(Explanation of Department Subfolder Permissions):**

The "ketoan" (accounting) subfolder and similarly the "nhansu" (HR) subfolder are configured with permissions granting access only to their respective department group ("ketoan" for "ketoan" subfolder, "nhansu" for "nhansu" subfolder) and the "quantri" (admin) group. Department subfolders are restricted to department groups and admins.

*   "ketoan1" subfolder (//Ado-Congviec/Ketoan/Ketoan1) access granted only to user "ketoan1" with high permissions (modify, delete, edit), but prevent deletion of the main "ketoan" folder. | Similar for remaining files.
*   ![image](https://github.com/user-attachments/assets/a95a9fd2-20b4-4e1a-9247-6d4157d48bcf)
*   ![image](https://github.com/user-attachments/assets/5a3b336a-3afe-4dc6-947b-3358a353f099)

**(Explanation of User Subfolder Permissions):**

Within each department subfolder (e.g., "ketoan"), individual user subfolders (e.g., "ketoan1") are created, and each user is granted "Modify," "Delete," and "Edit" (effectively Full Control except permission modification) permissions to *their own* subfolder.  Users have full control over their personal subfolders.  Permissions are also configured to prevent users from deleting the *main* department folder ("ketoan"), ensuring folder structure integrity.

**(Rationale for File Share Permissions Configuration):**

This detailed file share permission configuration implements a Role-Based Access Control (RBAC) model for shared work files, ensuring data security and access control based on user roles and departments.  Key aspects of the permission structure are:

*   **Centralized File Storage:**  The "Ado-Congviec" share provides a central repository for shared work files, improving collaboration and data management.
*   **Role-Based Access Control (RBAC):** Access is controlled through Active Directory groups, aligning permissions with user roles and departments.
*   **Administrator Full Control:** The "quantri" (admin) group has full control over the entire share, allowing administrators to manage permissions, files, and folder structure.
*   **Departmental Access Isolation:**  Department groups ("nhansu" and "ketoan") have read-only access to the root share and access to their respective department subfolders, ensuring data isolation between departments and preventing unauthorized access to other departments' files.
*   **User-Specific Personal Folders:** Each user has full control over their personal subfolder within their department folder, providing private work areas while still being within the shared organizational structure.
*   **Prevention of Accidental Deletion:**  Permissions are configured to prevent users from deleting main department folders, protecting the overall folder structure from accidental or malicious deletion.

**1.4. DNS Server + AD**

This section describes the configuration of the DNS server integrated with Active Directory to provide name resolution for internal and external resources, including resolving domain names for the DMZ web server within the LAN network.

Video 1:
https://github.com/user-attachments/assets/53c06928-1cb5-4105-a6ad-e95317550811

Video 2:
https://github.com/user-attachments/assets/f0956456-a838-42a1-80ea-a51beb9d0f6a

Configure DNS Manager to resolve domain names for the LAN network to the Web Server in the DMZ.

*   Create a forward lookup zone to convert domain names to IPs for the web servers: www.moviescope.com | Similar for www.goodshopping.com.
*   ![image](https://github.com/user-attachments/assets/58c5c21a-dd2b-4826-a897-4c74852f3e82)

**(Explanation of Forward Lookup Zone Creation):**

*   **Forward Lookup Zones:** Forward lookup zones are created in DNS Manager for the domain names "moviescope.com" and "goodshopping.com".  Forward lookup zones resolve domain names to IP addresses.
*   **Purpose:** Forward lookup zones are essential for enabling DNS resolution for web servers hosted in the DMZ. They allow internal LAN clients to access the web servers using their domain names (e.g., `www.moviescope.com`) instead of just IP addresses.

*   Integrate AD for management, granting full control to the "quantri" (admin) group.
*   ![image](https://github.com/user-attachments/assets/5c4667e2-ef52-448e-90b7-badaa49dfdcc)
*   ![image](https://github.com/user-attachments/assets/c13a6b6e-01af-4083-9e3d-af8903f8cb06)
*   ![image](https://github.com/user-attachments/assets/c73f5323-6381-4c62-90b2-29e96fddf738)

**(Explanation of AD Integration and Permissions for DNS):**

*   **AD Integration:** The DNS server is integrated with Active Directory. This means that DNS zone data is stored within Active Directory and replicated across domain controllers, providing centralized management and high availability for DNS services.  AD integration centralizes DNS management.
*   **"quantri" (admin) Group Permissions:** The "quantri" (admin) group is granted "Full Control" permissions over the DNS zones. This allows administrators (members of the "quantri" group) to fully manage DNS records, zones, and DNS server settings within the Active Directory integrated DNS environment. Admin group has full control over DNS management.

**(Rationale):** Integrating DNS with Active Directory simplifies DNS management and ensures consistency with Active Directory user and group management. Granting "quantri" (admin) group full control over DNS delegates DNS administration to authorized administrators.

*   Create a Host (A record) with the IP of the Web Server (DMZ) named "www" | Host (A) | IP of web server.
*   ![image](https://github.com/user-attachments/assets/b0f1fe7e-98f2-4275-b10c-2f23af766ac7)

**(Explanation of Host (A) Record Creation):**

*   **Host (A) Record:** A Host (A) record is created within the "moviescope.com" forward lookup zone with the following settings:
    *   **Name:** "www" -  The hostname part of the record, indicating the "www" subdomain (e.g., `www.moviescope.com`).
    *   **IP Address:** 192.168.40.254 -  The IP address of the web server in the DMZ (as defined in the network requirements).
*   **Purpose:** This A record maps the domain name `www.moviescope.com` to the IP address of the web server (192.168.40.254), enabling users on the LAN network to access the web server by typing `www.moviescope.com` in their web browsers.  A records map domain names to web server IPs.

*   Create a reverse lookup zone for the web server in the DMZ zone using the DMZ IP range | Similar for goodshopping.com web server
*   ![image](https://github.com/user-attachments/assets/7f864ac4-c60d-439e-b98e-8b032f25ac20)

**(Explanation of Reverse Lookup Zone Creation for DMZ Web Server):**

*   **Reverse Lookup Zone:** A reverse lookup zone is created for the 192.168.40.0/24 DMZ network.  Reverse lookup zones resolve IP addresses to domain names (reverse DNS lookup).
*   **Purpose:** Reverse lookup zones, while less critical for basic web access, can be useful for:
    *   **Troubleshooting and Diagnostics:**  Reverse DNS lookups can be used to verify DNS records and troubleshoot DNS resolution issues.
    *   **Logging and Auditing:** Some security and logging systems might use reverse DNS lookups to associate IP addresses with domain names for reporting and analysis.
    *   **Compliance:** In some cases, reverse DNS records might be required for compliance with certain security standards or regulations. Reverse lookup zones enable IP to domain name resolution.

*   Create a reverse lookup zone to convert IPs to domain names for moviescope.com web server | Similar for goodshopping.com web server.
*   ![image](https://github.com/user-attachments/assets/e4a923c8-65a9-40d3-91ba-bd6a01e97a62)

**(Explanation of Reverse Lookup Zone Configuration):**

This step likely involves creating Pointer (PTR) records within the reverse lookup zone to map the web server's IP address (192.168.40.254) back to its domain name (`www.moviescope.com`). PTR records enable reverse DNS lookups.

**(Summary of DNS Server Configuration):**

The DNS server is configured to provide both forward and reverse DNS resolution for the web servers hosted in the DMZ. Forward lookup zones map domain names to IP addresses, enabling LAN clients to access websites by URL. Reverse lookup zones map IP addresses back to domain names, which can be useful for troubleshooting, logging, and compliance purposes. The DNS server is integrated with Active Directory for centralized management and high availability, with administrative control delegated to the "quantri" (admin) group.

**1.5. FTP Server**

This section describes the configuration of an FTP server on the Active Directory server to provide file transfer capabilities for users on the LAN.

Video :
https://github.com/user-attachments/assets/66da41f3-ef28-4a13-a01b-0397fbfcec15

*   Create an FTP site on IIS with the path E:\Ado-Congviec created earlier.
*   ![image](https://github.com/user-attachments/assets/b6efa968-8e84-4fad-b31f-7425cc915b3d)

**(Explanation of FTP Site Creation in IIS):**

*   **FTP Site Creation:** An FTP (File Transfer Protocol) site is created on the Windows Server using Internet Information Services (IIS) Manager.  IIS is used to host the FTP site.
*   **Path:** "E:\Ado-Congviec" - The physical path for the FTP site is set to "E:\Ado-Congviec", which is the same folder that was configured as the "Ado-Congviec" file share in section III.1.3. This makes the shared folder accessible via both file sharing (SMB/CIFS) and FTP. FTP site path is set to the shared folder.

*   Windows Server IP address on Port 21.
*   ![image](https://github.com/user-attachments/assets/6811b1b9-296d-4158-81c2-9546e5d23b73)
*   ![image](https://github.com/user-attachments/assets/3d9c634e-d59e-4aec-8883-22971c10bf06)

**(Explanation of FTP Site Binding):**

*   **IP Address:** The FTP site is bound to the IP address of the Windows Server (AD Server), which is 192.168.30.100/24 in the LAN network. FTP site is bound to AD server IP.
*   **Port:** Port 21 - The FTP site is configured to listen on the standard FTP control port 21. FTP site listens on standard port 21.

*   Successful login to the FTP site with users from the "quantri" (admin) group.
*   ![image](https://github.com/user-attachments/assets/021dddeb-ce69-419b-87db-cd22f428bde9)

**(Verification of FTP Login - Admin Users):**

The report verifies successful login to the FTP site using user credentials from the "quantri" (admin) group. Admin users can successfully login to the FTP site.

*   Successful login to the FTP site accessing the "Ado-Congviec" file share.
*   ![image](https://github.com/user-attachments/assets/f9e8201a-5963-4444-b3ca-0ba364cf8115)

**(Verification of FTP File Share Access):**

The report verifies successful access to the "Ado-Congviec" file share through the FTP site. Users can access the file share via FTP.

**(Rationale for FTP Server Configuration):**

Configuring an FTP server provides another method for users on the LAN network to access and transfer files from the "Ado-Congviec" shared folder.  While FTP is less secure than SFTP or FTPS (as it transmits data and credentials in plain text), it is included in this lab setup as a common file transfer protocol and to demonstrate the configuration of a basic FTP service.  **Security Note:** In a production environment, SFTP or FTPS should be preferred for secure file transfer due to encryption.  FTP is included for demonstration purposes.

**2. Policies**

This section describes the implementation of Group Policies in Active Directory to enforce specific user environment settings and security policies on LAN client machines.

Video :
https://github.com/user-attachments/assets/d41df884-03f2-4037-802e-9dffb471afb3

**2.1. Hide Drive C:**

*   Hide drive C: for employees in the "ketoan" (accounting) group.
*   Create an OU named "Policy cho LAB" (Policy for LAB) in AD.
*   ![image](https://github.com/user-attachments/assets/c8a26a42-030d-443e-b28a-3261aa9e3824)

**(Explanation of Organizational Unit (OU) Creation):**

*   **Organizational Unit (OU) Creation:** An OU named "Policy cho LAB" (Policy for LAB) is created within Active Directory.  OUs are used to organize users and computers for applying Group Policies.
*   **Purpose:** Creating a dedicated OU allows you to apply Group Policies specifically to users and groups within that OU, providing granular control over policy application.  OUs enable targeted Group Policy application.

*   Move the "nhansu" (HR) and "ketoan" (accounting) groups into the newly created OU.
*   ![image](https://github.com/user-attachments/assets/33ad4947-239a-41df-b3b1-dd8557f2fad2)

**(Explanation of Group Membership in OU):**

*   **Group Movement to OU:** The "nhansu" (HR) and "ketoan" (accounting) groups are moved into the newly created "Policy cho LAB" OU.
*   **Rationale:** Moving these groups into the OU ensures that any Group Policy Objects (GPOs) linked to this OU will be applied to the users who are members of the "nhansu" and "ketoan" groups.  Moving groups to OU targets policies to specific users.

*   Create a GPO to apply policies to the OU (with added user groups) created in AD.
*   ![image](https://github.com/user-attachments/assets/578e026d-277c-4d08-ab11-d9df5af0855e)

**(Explanation of Group Policy Object (GPO) Creation):**

*   **Group Policy Object (GPO) Creation:** A new GPO is created within Active Directory.  GPOs are used to define and manage Group Policy settings.
*   **Linking GPO to OU:** This GPO is linked to the "Policy cho LAB" OU. This means that the policies defined within this GPO will be applied to users and computers within the "Policy cho LAB" OU (which currently includes the "nhansu" and "ketoan" groups). GPOs linked to OUs apply policies to OU members.

*   Enable "Hide these specified drives in My Computer" policy for drive C: within the GPO in the created OU in GPMC (Group Policy Management Console).
*   ![image](https://github.com/user-attachments/assets/7e168bc0-dd09-4b41-b7b9-ccbce502bcce)

**(Explanation of "Hide Drive C:" Policy Configuration):**

*   **GPO Setting:** The "Hide these specified drives in My Computer" policy is enabled within the newly created GPO. This is a User Configuration policy, meaning it applies to user settings.
*   **Drive Selection:**  Drive "C:" is selected as the drive to be hidden.
*   **Target Users:** This policy, because it's linked to the "Policy cho LAB" OU, will be applied to users in the "nhansu" (HR) and "ketoan" (accounting) groups who log in to domain-joined computers.
*   **Effect:** When users from the "ketoan" (accounting) group log in to their domain-joined workstations, drive C: will be hidden from Windows Explorer, restricting their access to the local C: drive.
*   **Rationale:** Hiding drive C: is a security policy often used to restrict user access to the local operating system drive and prevent accidental or intentional modification of system files or installation of unauthorized software, enhancing system security and data protection. Hiding drive C: enhances security by limiting user access to system drive.

**2.2. Disable Control Panel Access**

*   Create a GPO to apply the "disable Control Panel access" policy to the OU (with added user groups).
*   ![image](https://github.com/user-attachments/assets/3664e2de-dba5-4fba-a75a-6235876e423e)

**(Explanation of GPO Creation for Control Panel Restriction):**

*   **New GPO Creation (or Modification of Existing GPO):**  A new GPO is created (or the existing GPO created for hiding drive C: can be modified) and linked to the "Policy cho LAB" OU.  A GPO is created to manage Control Panel access policy.

*   Enable "Prohibit access to Control Panel and PC settings" policy to disable Control Panel access for users in the Groups moved to the OU during OU creation in AD.
*   ![image](https://github.com/user-attachments/assets/8fb15af9-28d2-40fa-b3ad-a0858178d1f2)

**(Explanation of "Disable Control Panel Access" Policy Configuration):**

*   **GPO Setting:** The "Prohibit access to Control Panel and PC settings" policy is enabled within the GPO. This is also a User Configuration policy.
*   **Target Users:** This policy, linked to the "Policy cho LAB" OU, will be applied to users in the "nhansu" (HR) and "ketoan" (accounting) groups.
*   **Effect:** When users from the "nhansu" and "ketoan" groups log in to their domain-joined workstations, access to the Control Panel and PC Settings will be disabled, preventing them from modifying system settings.
*   **Rationale:** Disabling Control Panel access is a security policy used to restrict users from changing system settings that could potentially compromise system security, install unauthorized software, or modify configurations in a way that could disrupt system operation.  Disabling Control Panel enhances security by restricting user system modifications.

**(Summary of Group Policy Configuration):**

Group Policies are implemented through GPOs linked to the "Policy cho LAB" OU to enforce security and user environment settings for users in the "nhansu" (HR) and "ketoan" (accounting) groups.  The policies configured in this lab are:

*   **Hide Drive C:** Restricts user access to the local C: drive in Windows Explorer.
*   **Disable Control Panel Access:** Prevents users from accessing and modifying Control Panel and PC Settings.

These policies are examples of basic security hardening and user environment management policies that can be centrally managed and enforced through Active Directory Group Policy.

**3. Network Monitoring with Splunk (Testing with Splunk)**

This section describes the configuration and testing of network security monitoring using Splunk, demonstrating how Splunk can be used to collect, analyze, and alert on security events from different network components.

*   **Existing Hosts:**
    *   AD Server: 192.168.30.100/24 (AD server) - Responsible for reporting and sending logs from LAN clients to Splunk.
    *   SERVER2022: 192.168.40.254/24 (Web Server) - Responsible for reporting and sending logs from the Web Server (DMZ) to Splunk.
![image](https://github.com/user-attachments/assets/54c64272-a2d4-4421-8e86-f6a111d47c60)

**(Explanation of Splunk Log Sources):**

*   **Splunk Data Sources:** Splunk is configured to collect logs from two main sources in this lab setup:
    *   **AD Server (192.168.30.100):** The Active Directory server is configured to forward Windows Event Logs (including security logs, system logs, and application logs) to the Splunk server.  The AD server acts as a log forwarder for LAN client events as well.
    *   **Web Server (SERVER2022 - 192.168.40.254):** The Web Server in the DMZ is configured to forward its web server logs (IIS logs, application logs, etc.) to the Splunk server.
*   **Centralized Logging:** Splunk acts as a centralized log management and Security Information and Event Management (SIEM) platform, collecting logs from various network devices and servers for security monitoring and analysis. Splunk provides centralized network security monitoring.

**3.1. Monitor Web Server and LAN (Snort, Splunk)**

This section demonstrates basic log monitoring in Splunk, showing how logs from the Web Server and LAN clients are collected and visualized in Splunk.

*   Successful login with user "ketoan3" (accounting3).
*   ![image](https://github.com/user-attachments/assets/f4a14182-0f2d-47b5-ba45-638471053836)

**(Verification of User Login):**

The report verifies a successful domain login by user "ketoan3" (accounting3).  This successful login event is logged and will be captured by Splunk.

*   Record logs in Splunk for the successful login of user "ketoan3" from LAN client 192.168.30.22.
*   ![image](https://github.com/user-attachments/assets/a860004c-3306-4455-865b-1626b5054663)
*   ![image](https://github.com/user-attachments/assets/570a14ba-3bd3-472e-9fc7-5474f81ce2fe)

**(Verification of Logs in Splunk):**

The images show that logs related to the successful login of user "ketoan3" are successfully ingested and displayed in the Splunk dashboard. Splunk successfully ingests and displays login logs.

*   --> Logs received from Web server and LAN.

**(Confirmation of Log Data Collection):**

Splunk is successfully receiving logs from both the Web server (DMZ) and LAN clients (via the AD server log forwarding). Splunk is receiving logs from both DMZ Web server and LAN clients.

**3.2. Brute Force Login**

This section demonstrates how Splunk can be used to detect brute-force login attempts on the LAN network and trigger alerts.

video :
https://github.com/user-attachments/assets/73c4ea2a-9b4c-4846-b0e9-0637d58f011b

*   Query for Brute Force logins to the LAN network.
*   ![image](https://github.com/user-attachments/assets/6a9f367d-46e9-42e4-9533-52542cbea74b)

**(Explanation of Splunk Brute Force Query):**

*   **Splunk Query:** A Splunk query is created to detect brute-force login attempts.  The query likely searches for Windows Security Event Logs (EventCode=4625 - Audit Failure) related to failed login attempts on the LAN network. The specific query shown in the image would need to be examined to confirm the exact syntax and search criteria.
*   **Purpose:** This query is designed to identify patterns of repeated failed login attempts, which are characteristic of brute-force attacks trying to guess user credentials. Splunk query detects brute-force login attempts.

*   Create an Alert to send warnings for the above query.
*   ![image](https://github.com/user-attachments/assets/e692580c-3da6-4d5a-a8cb-9c851cb6d57d)

**(Explanation of Splunk Alert Creation):**

*   **Splunk Alert:** A Splunk Alert is created based on the brute-force login query.  Splunk Alerts trigger notifications based on query results.
*   **Purpose:**  The alert is configured to automatically send warnings (e.g., email notifications, dashboard alerts) to administrators when the brute-force login query detects a threshold of failed login attempts within a specific timeframe. This enables real-time alerting for potential brute-force attacks. Splunk Alert triggers warnings for detected brute-force attempts.

*   A user can Remote Desktop to the AD server to test the Splunk Alert.
*   ![image](https://github.com/user-attachments/assets/432a9964-3db5-4d3a-b29a-10c2c89e9085)

**(Explanation of Testing Setup - Remote Desktop):**

A user (administrator or tester) attempts to connect to the AD server via Remote Desktop Protocol (RDP) to simulate user login activity and potentially trigger login events that Splunk will monitor.  RDP login is used for testing Splunk alert trigger.

*   Start testing on a Kali Linux machine | 192.168.19.165/24.
*   ![image](https://github.com/user-attachments/assets/a6d38769-3d05-4d90-8774-e8de5ffc0dcb)

**(Explanation of Testing Setup - Kali Linux):**

A Kali Linux machine (192.168.19.165/24) is used as the attacker machine to simulate a brute-force attack. Kali Linux is used as attacker machine for testing.

*   Use Hydra to Brute Force RDP to the AD server IP with test user "kiemthuAD" (testAD).
*   ![image](https://github.com/user-attachments/assets/9aaf8479-3d16-47a2-85ae-a5a80a3a161d)

**(Explanation of Brute Force Attack Simulation with Hydra):**

*   **Hydra Tool:** The Hydra password cracking tool (from Kali Linux) is used to simulate a brute-force attack.  Hydra is used to simulate brute-force attack.
*   **Target:** The target of the brute-force attack is the RDP service on the AD server (192.168.30.100).
*   **User:** The username "kiemthuAD" (testAD) is used as the target username for the brute-force attack.  Hydra attempts to guess the password for this user.

*   Brute Force attempts will generate failed logins, creating many EventCode=4625 events, which will trigger Splunk to send a Brute Force Alert.
*   ![image](https://github.com/user-attachments/assets/3b613bd3-f27d-4f77-abf0-7d5fd4345c99)

**(Explanation of Brute Force Attack Outcome - Event Logs):**

The brute-force attack simulation using Hydra generates a series of failed login attempts on the AD server. These failed login attempts are logged as Windows Security Event ID 4625 (Audit Failure - An account failed to log on). These Event 4625 logs are the data that Splunk will monitor to detect the brute-force attack. Event 4625 logs are generated by brute-force attempts.

*   Splunk recorded the logs and notified about the Brute Force attack as per the created Trigger.
*   ![image](https://github.com/user-attachments/assets/04bc5ba4-09ce-4a8e-91c4-5b9058509b84)

**(Verification of Splunk Alert - Brute Force Detection):**

The images show that Splunk successfully recorded the Event 4625 logs generated by the Hydra brute-force attack and triggered the configured alert, notifying administrators of the potential brute-force activity. Splunk successfully detects and alerts on brute-force attacks.

**(Summary of Splunk Brute Force Detection Testing):**

This section demonstrates that Splunk can be effectively used to detect brute-force login attempts by:

*   **Collecting Windows Security Event Logs:** Splunk collects relevant security logs from the AD server.
*   **Querying for Failed Login Events:** A Splunk query is used to identify Event ID 4625 logs indicating failed login attempts.
*   **Alerting on Brute Force Patterns:** A Splunk Alert is configured to automatically notify administrators when a threshold of failed login attempts is detected, providing real-time alerting for potential brute-force attacks.

**3.3. XSS Attack**

This section demonstrates how Splunk can be used to detect Cross-Site Scripting (XSS) attacks targeting the web server in the DMZ and trigger alerts.

video :
https://github.com/user-attachments/assets/72c0dd9e-93bb-41fe-8cdf-439bf1df4d97

*   Query to create an Alert for the issue of XSS attacks on the Web Server (DMZ).
*   ![image](https://github.com/user-attachments/assets/ba01ed4d-54ad-4d6d-919f-2ee0b553bfc9)
*   ![image](https://github.com/user-attachments/assets/d19f74a8-b093-46b8-aeca-ab8bae7cde9a)

**(Explanation of Splunk XSS Attack Query):**

*   **Splunk Query:** A Splunk query is created to detect potential XSS attacks targeting the web server in the DMZ. The query likely searches for web server logs (IIS logs in this case, as it's a Windows-based web server) for patterns or keywords indicative of XSS attempts. The specific query in the image needs further examination to understand the exact detection logic.
*   **Purpose:** This query aims to identify web requests containing malicious payloads or patterns commonly associated with XSS attacks, enabling detection of web application vulnerabilities being exploited. Splunk query detects XSS attack patterns in web server logs.

*   Test XSS attack on the Web Server (DMZ) from a client machine in the LAN.
*   ![image](https://github.com/user-attachments/assets/9ba8ecaf-dfb1-4980-af3c-e2c60e66d394)

**(Explanation of XSS Attack Simulation):**

*   **XSS Attack Test:** An XSS attack is simulated against the web server in the DMZ from a client machine in the LAN.  This simulation is likely performed by crafting a malicious URL or web request containing XSS payload and sending it to the web server. XSS attack is simulated from a LAN client to the DMZ web server.

*   Splunk recorded the logs and notified about the XSS attack as per the created Alert.
*   ![image](https://github.com/user-attachments/assets/928c4e3e-7fa6-4c8c-8175-69b28cac586b)

**(Verification of Splunk Alert - XSS Detection):**

The images show that Splunk successfully recorded logs related to the simulated XSS attack on the web server and triggered the configured alert, notifying administrators of the potential XSS attack. Splunk successfully detects and alerts on XSS attacks.

**(Summary of Splunk XSS Attack Detection Testing):**

This section demonstrates that Splunk can be used to detect XSS attacks by:

*   **Collecting Web Server Logs:** Splunk collects web server access logs from the DMZ web server.
*   **Querying for XSS Attack Patterns:** A Splunk query is used to identify log entries that match patterns indicative of XSS attacks.
*   **Alerting on XSS Attacks:** A Splunk Alert is configured to automatically notify administrators when potential XSS attacks are detected, enabling timely incident response.

**3.4. SQL Injection**

This section demonstrates how Splunk can be used to detect SQL Injection attacks targeting the web server in the DMZ and trigger alerts.

video :
https://github.com/user-attachments/assets/2f9a43d4-c98a-479c-9fb2-4dd1e3a724c8

*   Query to create an Alert for the issue of SQL Injection attacks on the Web Server (DMZ).
*   ![image](https://github.com/user-attachments/assets/e22d2c2e-2880-427d-9d4f-ecd7f78f27b8)

**(Explanation of Splunk SQL Injection Attack Query):**

*   **Splunk Query:** A Splunk query is created to detect potential SQL Injection attacks targeting the web server in the DMZ. The query likely searches web server logs for patterns or keywords indicative of SQL Injection attempts.  The specific query in the image needs further examination to understand the precise detection logic.
*   **Purpose:** This query aims to identify web requests containing malicious SQL code or patterns commonly associated with SQL Injection attacks, enabling detection of attempts to exploit SQL injection vulnerabilities. Splunk query detects SQL Injection attack patterns in web server logs.

*   Create an Alert for queries related to SQL Injection.
*   ![image](https://github.com/user-attachments/assets/d0a82372-22fe-47f8-bd33-345dce5e1bf4)

**(Explanation of Splunk Alert Creation for SQL Injection):**

*   **Splunk Alert:** A Splunk Alert is created based on the SQL Injection attack query.  Similar to the Brute Force Alert, this alert will trigger notifications when the SQL Injection query identifies suspicious activity. Splunk Alert triggers warnings for detected SQL Injection attempts.

*   From the Kali Linux machine, use sqlmap to perform SQL Injection attacks on the DMZ for testing.
*   ![image](https://github.com/user-attachments/assets/d14c137f-0d22-451e-8e2d-c375685bb448)

**(Explanation of SQL Injection Attack Simulation with sqlmap):**

*   **sqlmap Tool:** The sqlmap automated SQL injection tool (from Kali Linux) is used to simulate SQL Injection attacks against the web server in the DMZ. sqlmap is used to simulate SQL Injection attacks.
*   **Target:** The target of the sqlmap attack is the web application running on the DMZ web server (`www.moviescope.com`). sqlmap automatically probes the web application for SQL injection vulnerabilities and attempts to exploit them.

*   sqlmap will perform SQL Injection queries on the Web server www.moviescope.com in the DMZ, which will send logs to Splunk. If configured correctly, Splunk will send an Alert.
*   ![image](https://github.com/user-attachments/assets/53f7ad57-1e0d-433e-8065-428ba16a2d54)

**(Explanation of SQL Injection Attack Outcome - Web Server Logs):**

The SQL Injection attack simulation using sqlmap will generate web server logs on the DMZ web server. These logs will contain entries related to the SQL Injection attempts, which Splunk will collect and analyze. Web server logs record SQL Injection attempts.

*   Splunk recorded the logs and notified about the SQL Injection attack as per the created Alert.
*   ![image](https://github.com/user-attachments/assets/f28142f7-4e9c-4795-85ff-7e826aadef32)

**(Verification of Splunk Alert - SQL Injection Detection):**

The images show that Splunk successfully recorded the web server logs related to the sqlmap SQL Injection attack and triggered the configured alert, notifying administrators of the potential SQL Injection attack. Splunk successfully detects and alerts on SQL Injection attacks.

**(Summary of Splunk SQL Injection Attack Detection Testing):**

This section demonstrates Splunk's ability to detect SQL Injection attacks by:

*   **Collecting Web Server Logs:** Splunk collects web server access logs from the DMZ web server.
*   **Querying for SQL Injection Patterns:** A Splunk query is used to identify log entries that match patterns indicative of SQL Injection attacks.
*   **Alerting on SQL Injection Attacks:** A Splunk Alert is configured to automatically notify administrators when potential SQL Injection attacks are detected, enabling timely incident response to web application attacks.

**3.4. DoS Attack**

This section demonstrates how Splunk can be used to detect Denial-of-Service (DoS) attacks targeting the web server in the DMZ and trigger alerts.

video :
https://github.com/user-attachments/assets/2adf8e27-8872-419c-a967-652c8004fa9a

*   Query to create an Alert for the issue of DoS attacks on the Web Server (DMZ).
*   ![image](https://github.com/user-attachments/assets/eaa2f8f4-4cba-44b5-9b5d-fd8da0d2c6c4)

**(Explanation of Splunk DoS Attack Query):**

*   **Splunk Query:** A Splunk query is created to detect potential DoS attacks targeting the web server in the DMZ. The query likely searches web server logs for patterns indicative of DoS attacks, such as a high volume of requests from a single IP address or other DoS attack signatures.  The specific query in the image needs further examination to understand the exact detection logic.
*   **Purpose:** This query aims to identify abnormal traffic patterns that are characteristic of DoS attacks, such as a sudden surge in web requests, enabling detection of potential DoS attempts to overwhelm the web server. Splunk query detects DoS attack traffic patterns in web server logs.

*   Create an Alert for queries related to DoS attacks.
*   ![image](https://github.com/user-attachments/assets/b61dd41d-1fd5-4c43-b1d5-2bfda08cc365)

**(Explanation of Splunk Alert Creation for DoS Attacks):**

*   **Splunk Alert:** A Splunk Alert is created based on the DoS attack query.  Similar to the other alerts, this alert will trigger notifications when the DoS query detects suspicious traffic patterns. Splunk Alert triggers warnings for detected DoS attacks.

*   From the Kali Linux machine, perform a DoS attack on the DMZ web server (www.moviescope.com) to test the Alert function of Splunk.
*   ![image](https://github.com/user-attachments/assets/bee71453-2ec1-478d-8609-e7b0300c4ed1)

**(Explanation of DoS Attack Simulation with Overload):**

*   **Overload Tool:** The Overload tool (from Kali Linux) is used to simulate a Denial-of-Service (DoS) attack against the web server in the DMZ. Overload is used to simulate DoS attack.
*   **Target:** The target of the Overload DoS attack is the web server running on the DMZ (`www.moviescope.com`). Overload is used to generate a high volume of requests to overwhelm the web server.

*   Using Overload will create a DoS attack on the DMZ Web server, which will generate a large number of requests, causing Splunk to send an Alert.
*   ![image](https://github.com/user-attachments/assets/eb427f2c-d5e0-48da-909c-0951cebeea50)

**(Explanation of DoS Attack Outcome - Web Server Logs and Request Volume):**

The DoS attack simulation using Overload generates a large volume of web requests directed at the DMZ web server. This high volume of traffic is recorded in the web server logs, which Splunk will collect and analyze. DoS attack simulation generates high volume of web requests.

*   Splunk recorded the logs and notified about the DoS attack as per the created Alert.
*   ![image](https://github.com/user-attachments/assets/1fcb16d2-2141-46b5-b4a8-cba9e071f2c5)

**(Verification of Splunk Alert - DoS Detection):**

The images show that Splunk successfully recorded the web server logs generated by the Overload DoS attack and triggered the configured alert, notifying administrators of the potential DoS attack. Splunk successfully detects and alerts on DoS attacks.

**(Summary of Splunk DoS Attack Detection Testing):**

This section demonstrates Splunk's ability to detect DoS attacks by:

*   **Collecting Web Server Logs:** Splunk collects web server access logs from the DMZ web server.
*   **Querying for DoS Attack Patterns:** A Splunk query is used to identify log entries that match patterns indicative of DoS attacks, such as high request volume.
*   **Alerting on DoS Attacks:** A Splunk Alert is configured to automatically notify administrators when potential DoS attacks are detected, enabling rapid response to DoS incidents.

**End**

