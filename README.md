# Fortigate_Firewall_With_Splunk_Network_Monitoring


**Lab Report: Network Design and Implementation for a Small Business**

**I. Analysis**

**II. Implementation**

**1. Preparation**

**2. Design and Implement a Computer Network for a Small Business.** This network needs to meet the following requirements:

*   **Internet Connection:** The network must be connected to the Internet through a firewall. The public IP address of the firewall is 192.168.19.x.
*   **DMZ:** A DMZ is required to host a public web server. This web server will have the IP address 192.168.40.254/24.
*   **LAN:** The internal LAN network needs to support Active Directory services (including DHCP, DNS, and FTP), network security monitoring, and user authentication. The IP address range for the LAN is 192.168.30.0/24. The Active Directory server will have the IP address 192.168.30.100/24, and the Splunk server (network security monitoring) will have the IP address 192.168.30.21/24. LAN clients will receive dynamic IP addresses via DHCP from the AD server.
*   **Firewall:** The firewall must be configured to protect the network from external threats. It needs to support IDS/IPS, VPN, and firewall backup for redundancy. The firewall will have the IP address 192.168.19.x/24 for the WAN connection, 192.168.40.1/24 for the DMZ connection, and 192.168.30.1/24 for the LAN connection.
*   **Remote Access:** Administrators need to be able to remotely access the LAN network via VPN (using IPsec) for SSH and RDP.

**Tasks:**

1.  Draw a network diagram clearly showing all components, connections, and IP addresses.
2.  Detail the firewall configuration, including security policies, IDS/IPS, and VPN.
3.  Explain the Active Directory configuration, including DHCP, DNS, and FTP.
4.  Describe how administrators can securely connect to the LAN remotely, summarized in steps including SSH and Remote Desktop.
5.  Configure network security monitoring for the LAN and DMZ.

**2. Network Diagram**

![image](https://github.com/user-attachments/assets/e12f2336-e039-404a-8ff9-c9006080eded)

**3. Information**

| Device          | Zone        | IP Address        | Notes                                                 |
| --------------- | ----------- | ----------------- | ----------------------------------------------------- |
| Admin PC        | External    | N/A               | Connects to LAN via VPN                               |
| Internet        | External    | 192.168.19.2      | Connects to Firewall                                  |
| Firewall (WAN)  | DMZ         | 192.168.19.x/24   | Connects to Internet, DMZ, and LAN                    |
| Firewall (LAN)  | LAN         | 192.168.30.1/24   | Connects to Splunk and AD server                        |
| DMZ Server      | DMZ         | 192.168.40.254/24 | Public Web Server                                     |
| Splunk Server   | LAN         | 192.168.30.21/24  | Data Analysis Server                                   |
| AD Server       | LAN         | 192.168.30.100/24 | Issues IP addresses to LAN devices via DHCP           |
| LAN Client      | LAN         | DHCP              | Receives IP address from AD Server                      |
| Existing Websites | N/A       | www.goodshopping.com, www.moviescope.com | Websites used for testing and demonstration |

**3. Functions/Services**

| Zone        | Function/Service                                      | Notes                                                              |
| ----------- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| LAN         | - Active Directory (DHCP, DNS, FTP) - Policies - Network Security Monitoring - User Authentication | Main internal network for employees and internal devices.          |
| DMZ         | - Web Server                                          | Hosts public servers, isolated from the internal LAN.             |
| Firewall    | - Rules - IDS | IPS - VPN - Backup Firewall                 | Acts as a security gateway, located between the Internet and internal networks (LAN, DMZ). |
| Admin PC (Internet) | - SSH - RDP - VPN | IPsec                               | Allows Admin to SSH and Remote Desktop into the LAN via VPN (+ IPsec). |

**II. FortiGate Firewall Setup**

**1. Firewall Information**

*   Port 1 = WAN
*   Port 2 = LAN
*   Port 3 = DMZ

| Port  | Mode   | IPv4 Address      |
| ----- | ------ | ----------------- |
| port1 | DHCP   | 192.168.19.162    |
| port2 | Static | 192.168.30.1      |
| port3 | Static | 192.168.40.1      |

![image](https://github.com/user-attachments/assets/e38e8dc0-d9ee-4ffc-a9b6-5abda6098890)


**2. Firewall Rules**

**2.1. Rules for LAN**

*   **Allow LAN access to WEB (Internal DMZ web access only, block public Internet web access) | Allow Ping for connection testing.**
    *   Ports: 443, 80, 53, ICMP/8

 ![image](https://github.com/user-attachments/assets/76f576b0-89fa-48cb-b4bf-bb2955f5cd79)
 ![image](https://github.com/user-attachments/assets/58c1f0b1-5cf3-4d39-bfb5-cf0b2fdb049c)


*   **Open VPN to LAN network for administrators with services like SSH, RDP, PING, IKE (VPN tunnel). | Allow Ping for connection testing.**
    *   Ports: 500, 4500, 3389, 22, ICMP/8
 
![image](https://github.com/user-attachments/assets/f583a539-8380-4465-a62a-e264d42c21d1)


**2.1. Rules for DMZ**

*   **Open port for the DMZ zone to only send logs to the Splunk server in the LAN for network security monitoring.**
    *   Port: 9997
![image](https://github.com/user-attachments/assets/b7d70a72-fc7d-4e3a-8f7b-053aadc1d42a)

**2.2. Rules for WAN**

*   **Open port for users outside the internet to access the web server in the DMZ. And ping for testing.**
    *   Ports: 443, 80, 53, ICMP/8
![image](https://github.com/user-attachments/assets/9eef9944-92f2-40b5-adb7-68b314ffc929)

**3. VPN Tunnel**

Configure VPN for administrator remote access to the LAN network.

*   **VPN Group:** named "ado-group" containing VPN members (ado).

![image](https://github.com/user-attachments/assets/e82c3f05-6e22-4048-9a5c-cdd29c5727cd)

*   **VPN Tunnel:** named "Ado-VPN", type Remote Access.
*   ![image](https://github.com/user-attachments/assets/b4d4cba3-c383-442f-b964-56b06005b2ba)

    *   Incoming interface: WAN port.
    *   Pre-shared key: 12345678.
    *   Authorization: ado-group.
    *   ![image](https://github.com/user-attachments/assets/18bfbb3f-68f6-4fc3-ac9a-4a2b05df653d)

    *   Local interface: LAN.
    *   VPN IP range to assign: 1.1.1.1-1.1.1.5/32.
    *   ![image](https://github.com/user-attachments/assets/c6aea50e-65ce-4242-80c6-4791e9162e1a)


We will have 
![image](https://github.com/user-attachments/assets/e0a5bdb3-143c-4b1e-87e2-d638e7d43db6)



**4. IPS / IDS**

Monitor and prevent attacks with IPS and IDS from external networks (WAN) and internal networks (LAN) to the Server (DMZ).
![image](https://github.com/user-attachments/assets/4e64e6de-7e8e-4322-877b-2bc9ccd1d878)
![image](https://github.com/user-attachments/assets/03933ea4-658f-4e1a-ac37-334014294f11)
![image](https://github.com/user-attachments/assets/d622e67a-b422-4f8d-8815-f42043694bb0)


*   Use WAF and IPS for protection. WAF will also act as IDS-IPS to handle XSS and SQL injection.
*   Alert warnings for XSS attacks and block SQL Injection attacks.
![image](https://github.com/user-attachments/assets/55b26fd4-33dc-4baf-a2ee-1f98bdd2a469)

**5. Firewall Backup Rule**

*   Download the backup file after completing firewall setup for redundancy during Restore.
*   ![image](https://github.com/user-attachments/assets/739e72fa-5d52-4c5b-bb2f-ad9bf4cdf63d)
*   Encrypt the backup file for security.
*   ![image](https://github.com/user-attachments/assets/25b5339f-52b5-4b10-ac22-20765dc2124d)
*   Save the Firewall Backup File to be used for Restore.
*   ![image](https://github.com/user-attachments/assets/158bbc50-b3c2-42cb-8b61-88a61de02706)


**III. LAN Setup**

**1. (AD, DHCP, DNS, FTP) Server**

**1.1. DHCP Server**

*   Create a DHCP Scope for the LAN network named "LAN".
*   ![image](https://github.com/user-attachments/assets/1c9999ca-6841-4b4c-b8dc-deda3f8ca735)

*   IP address range for this scope to assign: 192.168.30.20 - 192.168.30.254/24.
*   ![image](https://github.com/user-attachments/assets/bf85ce8d-040d-4713-9611-253d55f80377)

*   No special IP ranges excluded by DHCP.
*   ![image](https://github.com/user-attachments/assets/695065fa-dbd7-4ccb-a98f-1729fcf8262f)

*   Gateway assigned by this DHCP Scope is the Firewall IP for Firewall management.
*   ![image](https://github.com/user-attachments/assets/6372ed97-9bb1-4644-9bb5-7b454d5fa932)

Total 
![image](https://github.com/user-attachments/assets/9edef7dc-c0c2-4e59-af07-19670463d89a)

**1.2. User Authentication**

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


*   Successful Domain login with the users created.

**1.3. User Permissions**

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


*   Share the "Ado-Congviec" (Ado-Work) file share for the groups.
*   ![image](https://github.com/user-attachments/assets/9a4e8808-8f5a-45e5-8e19-c347d8bab569)
*   ![image](https://github.com/user-attachments/assets/f23812b6-1872-445f-b1b9-7231910e5e6f)



*   Map the work file drive to drive Z: for Users (similar for other Users).
*   ![image](https://github.com/user-attachments/assets/1e9a4264-d3a0-4b3f-ac02-97c2509b42b6)




*   Full control for "quantri" (admin) group on the master "Ado-Congviec" folder.
*   ![image](https://github.com/user-attachments/assets/5b617e7a-80fc-40be-998e-d0b4c85cc8da)
*   ![image](https://github.com/user-attachments/assets/ed9983da-045e-42bd-b0cf-dde957845bbb)





*   Read-only permission for "nhansu" (HR) and "ketoan" (accounting) groups on the master "Ado-Congviec" folder.
*   ![image](https://github.com/user-attachments/assets/3ce06f7b-27c3-459f-a584-39c21f0ae749)
*   ![image](https://github.com/user-attachments/assets/d5c0d734-a901-427f-95ad-6355ac7da396)





*   "ketoan" subfolder access only for "ketoan" (accounting) and "quantri" (admin) groups (similar for "nhansu" subfolder).
*   ![image](https://github.com/user-attachments/assets/438a4b55-23d9-4205-8d7d-6ccf972d73fd)
*   ![image](https://github.com/user-attachments/assets/b987080f-502d-4e60-bc43-b526cab725c2)




*   "ketoan1" subfolder (//Ado-Congviec/Ketoan/Ketoan1) access granted only to user "ketoan1" with high permissions (modify, delete, edit), but prevent deletion of the main "ketoan" folder. | Similar for remaining files.
*   ![image](https://github.com/user-attachments/assets/a95a9fd2-20b4-4e1a-9247-6d4157d48bcf)
*   ![image](https://github.com/user-attachments/assets/5a3b336a-3afe-4dc6-947b-3358a353f099)




**1.4. DNS Server + AD**

Configure DNS Manager to resolve domain names for the LAN network to the Web Server in the DMZ.

*   Create a forward lookup zone to convert domain names to IPs for the web servers: www.moviescope.com | Similar for www.goodshopping.com.
*   ![image](https://github.com/user-attachments/assets/58c5c21a-dd2b-4826-a897-4c74852f3e82)
  

*   Integrate AD for management, granting full control to the "quantri" (admin) group.
*   ![image](https://github.com/user-attachments/assets/5c4667e2-ef52-448e-90b7-badaa49dfdcc)
*   ![image](https://github.com/user-attachments/assets/c13a6b6e-01af-4083-9e3d-af8903f8cb06)
*   ![image](https://github.com/user-attachments/assets/c73f5323-6381-4c62-90b2-29e96fddf738)



*   Create a Host (A record) with the IP of the Web Server (DMZ) named "www" | Host (A) | IP of web server.
*   ![image](https://github.com/user-attachments/assets/b0f1fe7e-98f2-4275-b10c-2f23af766ac7)



*   Create a reverse lookup zone for the web server in the DMZ zone using the DMZ IP range | Similar for goodshopping.com web server
*   ![image](https://github.com/user-attachments/assets/7f864ac4-c60d-439e-b98e-8b032f25ac20)



*   Create a reverse lookup zone to convert IPs to domain names for moviescope.com web server | Similar for goodshopping.com web server.
*   ![image](https://github.com/user-attachments/assets/e4a923c8-65a9-40d3-91ba-bd6a01e97a62)




**1.5. FTP Server**

*   Create an FTP site on IIS with the path E:\Ado-Congviec created earlier.
*   ![image](https://github.com/user-attachments/assets/b6efa968-8e84-4fad-b31f-7425cc915b3d)
*   

*   Windows Server IP address on Port 21.
*   ![image](https://github.com/user-attachments/assets/6811b1b9-296d-4158-81c2-9546e5d23b73)
*   ![image](https://github.com/user-attachments/assets/3d9c634e-d59e-4aec-8883-22971c10bf06)


*   Successful login to the FTP site with users from the "quantri" (admin) group.
*  ![image](https://github.com/user-attachments/assets/021dddeb-ce69-419b-87db-cd22f428bde9)



*   Successful login to the FTP site accessing the "Ado-Congviec" file share.
*   ![image](https://github.com/user-attachments/assets/f9e8201a-5963-4444-b3ca-0ba364cf8115)





**2. Policies**

**2.1. Hide Drive C:**

*   Hide drive C: for employees in the "ketoan" (accounting) group.
*   Create an OU named "Policy cho LAB" (Policy for LAB) in AD.
*   ![image](https://github.com/user-attachments/assets/c8a26a42-030d-443e-b28a-3261aa9e3824)



*   Move the "nhansu" (HR) and "ketoan" (accounting) groups into the newly created OU.
*   ![image](https://github.com/user-attachments/assets/33ad4947-239a-41df-b3b1-dd8557f2fad2)




*   Create a GPO to apply policies to the OU (with added user groups) created in AD.
*   ![image](https://github.com/user-attachments/assets/578e026d-277c-4d08-ab11-d9df5af0855e)



*   Enable "Hide these specified drives in My Computer" policy for drive C: within the GPO in the created OU in GPMC (Group Policy Management Console).
*   ![image](https://github.com/user-attachments/assets/7e168bc0-dd09-4b41-b7b9-ccbce502bcce)





**2.2. Disable Control Panel Access**

*   Create a GPO to apply the "disable Control Panel access" policy to the OU (with added user groups).
*   ![image](https://github.com/user-attachments/assets/3664e2de-dba5-4fba-a75a-6235876e423e)



*   Enable "Prohibit access to Control Panel and PC settings" policy to disable Control Panel access for users in the Groups moved to the OU during OU creation in AD.
*   ![image](https://github.com/user-attachments/assets/8fb15af9-28d2-40fa-b3ad-a0858178d1f2)




**3. Network Monitoring with Splunk (Testing with Splunk)**

*   **Existing Hosts:**
    *   AD Server: 192.168.30.100/24 (AD server) - Responsible for reporting and sending logs from LAN clients to Splunk.
    *   SERVER2022: 192.168.40.254/24 (Web Server) - Responsible for reporting and sending logs from the Web Server (DMZ) to Splunk.
![image](https://github.com/user-attachments/assets/54c64272-a2d4-4421-8e86-f6a111d47c60)


**3.1. Monitor Web Server and LAN (Snort, Splunk)**

*   Successful login with user "ketoan3" (accounting3).
*   ![image](https://github.com/user-attachments/assets/f4a14182-0f2d-47b5-ba45-638471053836)


*   Record logs in Splunk for the successful login of user "ketoan3" from LAN client 192.168.30.22.
*   ![image](https://github.com/user-attachments/assets/a860004c-3306-4455-865b-1626b5054663)
*   ![image](https://github.com/user-attachments/assets/570a14ba-3bd3-472e-9fc7-5474f81ce2fe)


*   --> Logs received from Web server and LAN.

**3.2. Brute Force Login**

*   Query for Brute Force logins to the LAN network.
*   ![image](https://github.com/user-attachments/assets/6a9f367d-46e9-42e4-9533-52542cbea74b)



*   Create an Alert to send warnings for the above query.
*   ![image](https://github.com/user-attachments/assets/e692580c-3da6-4d5a-a8cb-9c851cb6d57d)



*   A user can Remote Desktop to the AD server to test the Splunk Alert.
*   ![image](https://github.com/user-attachments/assets/432a9964-3db5-4d3a-b29a-10c2c89e9085)



*   Start testing on a Kali Linux machine | 192.168.19.165/24.
*   ![image](https://github.com/user-attachments/assets/a6d38769-3d05-4d90-8774-e8de5ffc0dcb)



*   Use Hydra to Brute Force RDP to the AD server IP with test user "kiemthuAD" (testAD).
*   ![image](https://github.com/user-attachments/assets/9aaf8479-3d16-47a2-85ae-a5a80a3a161d)



*   Brute Force attempts will generate failed logins, creating many EventCode=4625 events, which will trigger Splunk to send a Brute Force Alert.
*   ![image](https://github.com/user-attachments/assets/3b613bd3-f27d-4f77-abf0-7d5fd4345c99)




*   Splunk recorded the logs and notified about the Brute Force attack as per the created Trigger.
*   ![image](https://github.com/user-attachments/assets/04bc5ba4-09ce-4a8e-91c4-5b9058509b84)


**3.3. XSS Attack**

*   Query to create an Alert for the issue of XSS attacks on the Web Server (DMZ).
*   ![image](https://github.com/user-attachments/assets/ba01ed4d-54ad-4d6d-919f-2ee0b553bfc9)
*   ![image](https://github.com/user-attachments/assets/d19f74a8-b093-46b8-aeca-ab8bae7cde9a)





*   Test XSS attack on the Web Server (DMZ) from a client machine in the LAN.
*   ![image](https://github.com/user-attachments/assets/9ba8ecaf-dfb1-4980-af3c-e2c60e66d394)



*   Splunk recorded the logs and notified about the XSS attack as per the created Alert.
*   

**3.4. SQL Injection**

*   Query to create an Alert for the issue of SQL Injection attacks on the Web Server (DMZ).
*   Create an Alert for queries related to SQL Injection.
*   From the Kali Linux machine, use sqlmap to perform SQL Injection attacks on the DMZ for testing.
*   sqlmap will perform SQL Injection queries on the Web server www.moviescope.com in the DMZ, which will send logs to Splunk. If configured correctly, Splunk will send an Alert.
*   Splunk recorded the logs and notified about the SQL Injection attack as per the created Alert.

**3.4. DoS Attack**

*   Query to create an Alert for the issue of DoS attacks on the Web Server (DMZ).
*   Create an Alert for queries related to DoS attacks.
*   From the Kali Linux machine, perform a DoS attack on the DMZ web server (www.moviescope.com) to test the Alert function of Splunk.
*   Using Overload will create a DoS attack on the DMZ Web server, which will generate a large number of requests, causing Splunk to send an Alert.
*   Splunk recorded the logs and notified about the DoS attack as per the created Alert.

**IV. Video Demonstrations**

1.  VPN - Remote Desktop - SSH (Video file: VPN)
2.  DHCP (AD) - Client (Video file: DHCP)
3.  DNS (AD) - Client (Video file: DNS)
4.  IPS - IDS (Video file: IPS-IDS)
5.  FTP (Video file: FTP)
6.  User Authentication (Video file: Xác Thực Người DÙng)
7.  User Permissions (Video file: Phân quyền người dùng)
8.  Policies (Video file: Policy)
9.  Backup - Restore Firewall (Video file: BackRule)
10. Network Monitoring with Splunk (Video file: Splunk)



**End**
