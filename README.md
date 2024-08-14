# OTC Net Config

A PowerShell script designed to assist in configuring network settings, managing echo requests, scanning local networks, and displaying active network information on Windows systems. 

## Description

OTC Net Config is a comprehensive tool aimed at simplifying various network configuration tasks for users in a classroom or lab environment. This script provides an interactive menu that allows users to configure echo requests, set IP addresses, scan local networks, and retrieve network settings, among other functionalities.

Key features include:
- **Echo Request Configuration:** Easily enable or disable echo requests (ICMP) through the Windows Firewall.
- **IP Configuration Wizard:** Automatically configure IP addresses, gateways, and DNS settings based on classroom and computer numbers.
- **Network Information Display:** View active network adapters, connections, and packet statistics.
- **Local Network Scan:** Identify active hosts within a specified subnet, complete with hostname resolution.
- **Studata Drive Mapping (WIP):** Map network drives using OTC credentials.
- **About Section:** Provides links to other projects and tools developed by the author.

The script is designed to be user-friendly, requiring minimal input to perform complex network tasks, making it ideal for educational settings where multiple computers need consistent configuration.

## Getting Started

### Prerequisites
- **Windows PowerShell 5.1 or later** is required to run this script.
- **Administrator privileges** are necessary to execute certain functions such as IP configuration and firewall adjustments.

### Installation
1. **Download the Script:**
   - Clone the repository or download the script file directly.
   - Save the script in a directory of your choice, for example: `C:\Scripts\OTCNetConfig.ps1`

2. **Run the Script:**
   - Open PowerShell as an administrator.
   - Navigate to the directory where the script is saved.
   - Execute the script using the following command:
     ```powershell
     .\OTCNetConfig.ps1
     ```
   - The script will check for administrator privileges and restart with elevated permissions if necessary.

### Usage
1. Upon running the script, you will be presented with a menu with several options:
   - **Configure Echo Requests:** Toggle ICMP echo requests (ping) on or off.
   - **Display Network Info:** Show detailed information about your network adapters and active connections.
   - **IP Configuration Wizard:** Set up your network settings based on your classroom and computer number.
   - **Network Host Scan:** Scan the local subnet for active devices.
   - **About:** View other projects or exit the script.

2. Follow the on-screen prompts to perform your desired task.

3. To exit the script, select the "Exit" option from the menu.
