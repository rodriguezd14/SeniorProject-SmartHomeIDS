# Smart Home IDS Project

## Overview

The Smart Home IDS Project captures network traffic, analyzes the captured data, and displays the results through a web-based dashboard.

> **Note:** For testing purposes, use an Ubuntu Desktop virtual machine.

---

## Setup

### 1. Install Suricata
Run these commands:
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
```
Verify suricata has been installed
```bash
suricata --build-info
```
Edit the suricata file and add the network address your device is connected to and add the interface
```bash
sudo nano /etc/suricata/suricata.yaml
```
<img width="778" height="200" alt="image" src="https://github.com/user-attachments/assets/5ac9ab1c-7acc-453c-a0f8-a10398655414" />
<img width="753" height="131" alt="image" src="https://github.com/user-attachments/assets/68148fc4-d94f-41a0-84e3-b641580a186a" />
(it might be a good idea to use sublime to make it faster to find and make the changes)
Update suricate
```bash
sudo suricata-update
```
Start and enable suricata to run in the background
```bash
sudo systemctl enable suricata
sudo systemctl start suricata
```
Run an nmap scan on the machine then see if the log captures it
```bash
sudo tail -f /var/log/suricata/fast.log
```


### 2. Clone github repo into your directory

Cd into the folder

```bash
cd SeniorProject-SmartHomeIDS
```

### 3. Change the network interface in server.py to the one your machines uses

<img width="753" height="141" alt="image" src="https://github.com/user-attachments/assets/9bea0f7c-18ae-48bb-966f-bfaf1555ce80" />

should be on line 22 if that helps


---

### 4. Install python packages
when you run
```bash
python3 server.py
```
You may need to install some python packages for that just run the following
```bash
sudo apt install python3-flask
sudo apt install python3-scapy
```
Those should be only two you need

### 5. Running server.py
After you've installed the packages you are ready to run
```bash
server.py
```
simply type
```bash
sudo python3 server.py
```

## Viewing the Dashboard

Open a web browser in the VM and navigate to:

```text
http://<VM_IP_ADDRESS>:8000
```

Example:

```text
http://192.168.1.100:8000
```

The dashboard should load and display the analyzed network traffic data.

---



