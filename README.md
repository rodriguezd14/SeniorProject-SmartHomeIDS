# Smart Home IDS Project

## Overview

The Smart Home IDS Project captures network traffic, analyzes the captured data, and displays the results through a web-based dashboard.

> **Note:** For testing purposes, use an Ubuntu Desktop virtual machine.

---

## Setup

### 1. Clone github repo into your directory

Cd into the folder

```bash
cd SeniorProject-SmartHomeIDS
```

### 2. Change the network interface in server.py to the one your machines uses

<img width="753" height="141" alt="image" src="https://github.com/user-attachments/assets/9bea0f7c-18ae-48bb-966f-bfaf1555ce80" />
should be on line 22 if that helps


---

### 3. Install python packages
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

### 4. Running server.py
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



