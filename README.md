# SDN_CAMPUS_AUTHENTICATION_RADIUS_POX_Controller
A Campus Area Network (CAN) connects multiple local area networks (LANs) within a limited geographical area, such as a university campus or corporate complex. Unlike Wide Area Networks (WANs) or Metropolitan Area Networks (MANs), CANs are confined to smaller areas, providing efficient and reliable connectivity for numerous users and devices. Traditional authentication systems in CANs struggle to meet security demands in today's dynamic environment with the growing number of devices and users, leading to vulnerabilities such as unauthorized access.

This project presents an SDN-based authentication system designed to enhance authentication in CANs. The system uses SDN’s centralized control plane for scalable management and employs a POX controller to enforce robust user authentication. The RADIUS protocol, a component of the 802.1x standard, is integrated for secure verification of user identities, reducing the risk of unauthorized access. The system does not require new protocols or additional configuration for existing devices, simplifying deployment and maintenance. Testing shows that this approach enhances network security through effective authentication tailored for CAN environments.

## Problem Statement
Educational institutions face an increasing number of cyber attacks due to the vast amount of sensitive data stored online. Traditional network security measures in CANs are insufficient to protect against sophisticated threats like data theft, ransomware, and DDoS attacks. Common vulnerabilities include:

1. Data Theft: Institutions store sensitive student and staff data, leading to identity theft, financial loss, and reputational harm.
2. Research Data Theft: Attackers target valuable research data for financial gain.
3. Ransomware Attacks: Often result from compromised credentials, leading to encrypted critical data.
4. DDoS Attacks: Disrupt online services and productivity by overwhelming network resources.
This project integrates SDN with RADIUS to enhance authentication on campus networks, addressing these security flaws and improving the user experience and overall campus security.

## RADIUS Server
RADIUS (Remote Authentication Dial-In User Service) is a protocol for remote user authentication and accounting. Commonly used in business, education, and ISP networks, it performs Authentication, Authorization, and Accounting (AAA) functions. The RADIUS server verifies user credentials against its database and authorizes access based on predefined policies.

### Key Characteristics (RFC2865)
1. Client/Server Model: The RADIUS protocol operates in a client/server architecture:

2. Network Access Server (NAS): Acts as the client, collecting user login information and sending it to the RADIUS server for verification.
3. RADIUS Server: Verifies user credentials and responds with access permissions or denial based on policies.
4. Proxy Capabilities: The RADIUS server can function as a proxy, routing requests to other servers, enhancing scalability and flexibility.
5. Network Security:

5.1. Shared Secret: Encrypts data between the NAS and RADIUS server using a pre-configured shared string for secure communication.

5.2. Encrypted Passwords: User passwords are encrypted during transmission using MD5 hashing for security.
## POX Controller
POX is a Python-based software framework that supports network programming, particularly for OpenFlow switches. Its components are Python modules that simplify and optimize development. POX is used in this project to manage network traffic and enforce authentication policies within the SDN environment.

## Mininet
Mininet is a network emulation platform that simulates virtual hosts, switches, routers, and connections on a single machine. It allows testing of the same applications and binaries used in real networks, providing a realistic environment for developing and validating network architectures.

## Architecture
The proposed SDN authentication system focuses on enhancing user experience and security using the 802.1x standard. The architecture includes:

1. OpenFlow-enabled Switches
2. Controller
3. Authenticator
4. Authentication Server
When a new device connects, the controller checks if the user is authenticated. If not, the device is redirected to a web interface for credential entry. The RADIUS server authenticates the credentials, and the controller configures the network switch based on the authentication outcome. This setup ensures robust and scalable user authentication.

## Authentication Process
When a client sends a packet, the POX controller verifies the client’s MAC address against the local database (AuthDB). If authenticated, the controller checks session validity. If the session has expired or the client is unauthenticated, the client is redirected to the web interface for credential entry.

The web interface forwards login credentials to the RADIUS server, which processes the request:

If valid, the server responds with an "Access-Accept" message and the client’s IP address.
If invalid, an "Access-Reject" message is issued.
Upon successful authentication, the web interface sends the client’s details to the POX controller, which updates the AuthDB and installs flow rules for the authenticated user, ensuring secure network access.

The POX controller continuously monitors sessions, managing expired sessions by redirecting clients for re-authentication to maintain network security. This process ensures only authenticated users access the network, preserving robust security and efficient user management. 

## Note
This repository contains a modified version of l2_learning.py, which is part of the POX controller, and includes the logic for handling authentication. Additionally, it includes auth_db.py, which contains the logic for adding authenticated clients to the database. An important component of the system is the RADIUS server; its configuration involves only minor adjustments to add the client from which the RADIUS server will receive authentication requests. The repository also includes pcap files used during testing and a sample Mininet topology for network emulation and validation of the authentication system.

## Basic Commands
1. Running the POX Controller with l2_learning.py
Make sure you are in the POX directory. Run the POX controller with the modified l2_learning.py script:

cd /path/to/pox
./pox.py forwarding.l2_learning

2. Running auth_db.py
In a separate terminal, navigate to the location where auth_db.py is stored and run it using Python:


cd /path/to/auth_db
python3 auth_db.py

3. Running Mininet with a Custom Topology
Make sure Mininet is installed, and then run it using a custom topology:


sudo mn --custom /path/to/topology.py --topo mytopo --controller=remote,ip=127.0.0.1,port=6633 --mac --arp

Replace /path/to/topology.py with the path to your topology file.
Adjust mytopo to match the name of the topology defined in your script.
Ensure the IP and port match those of the POX controller.

4. Running Wireshark
Start Wireshark with root privileges to capture traffic:

sudo wireshark

Once Wireshark opens, select the network interface connected to Mininet’s virtual network (e.g., lo, eth0).
Apply filters like radius or openflow_v1 to focus on relevant traffic.

### Additional Tips:
Always run Mininet and Wireshark with sudo as they require elevated privileges to manage network interfaces and capture packets.
Ensure your POX controller and other Python scripts are executable and have the necessary dependencies installed.
