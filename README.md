# 📡 Network Monitoring and Remote Control System

## 📖 Overview
This project is a network monitoring and remote control system developed in Python. It is capable of discovering devices connected to a local network, collecting information about active users, and enabling remote interaction between machines.

The system leverages both UDP and TCP protocols to provide efficient discovery and reliable communication. It also implements authentication, authorization, and cryptographic mechanisms to ensure secure and controlled access between nodes.

---

## ⚙️ Architecture & Specifications

### 📡 Device Discovery (UDP Broadcast)
- Uses **UDP broadcast** to discover devices on the local network.
- Clients listen for broadcast messages and respond with their identification data.
- This approach allows fast and scalable discovery without prior knowledge of network nodes.

---

### 🔗 Communication (TCP)
- All persistent communication is handled via **TCP connections**.
- Ensures:
  - Reliable data transfer  
  - Ordered packet delivery  
  - Connection-oriented communication  
- Used for:
  - User data exchange  
  - Remote command execution  
  - Secure communication between nodes  

---

### 🔐 Security (Authentication, Authorization & Encryption)

#### 👤 Authentication
- Clients must authenticate before establishing full communication.
- Ensures that only legitimate users/devices can access the system.

#### 🛡️ Authorization
- After authentication, the system enforces authorization rules.
- Defines what actions each user/device is allowed to perform.
- Prevents unauthorized remote control or data access.

#### 🔑 Key Exchange – RSA
- Uses **RSA (asymmetric encryption)** for secure key exchange.
- Protects the initial handshake and credential exchange.

#### 🔒 Data Encryption – AES
- After key exchange, communication switches to **AES (symmetric encryption)**.
- Ensures efficient and secure data transmission.

---

## 🧠 Features

- 🔍 Network discovery via UDP broadcast  
- 👥 Detection of active users  
- 🔐 Authentication of clients  
- 🛡️ Authorization control for actions  
- 🔗 Reliable TCP-based communication  
- 🔑 Secure key exchange using RSA  
- 🔒 Encrypted communication using AES  
- 🖥️ Remote control between authorized devices  

---

## 🛠️ Technologies

- Python  
- Socket Programming (TCP/UDP)  
- Cryptography (RSA, AES)  

---

## ⚠️ Disclaimer
This project is intended for **educational purposes only**.  
Unauthorized use on networks without proper permission may violate security and privacy policies.
