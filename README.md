# ZigStrike

<img src="https://github.com/0xsp-SRD/0xsp.com/blob/main/images/3e209efa-4228-4119-b9dc-590a0aa183cb.jpeg" width=50% height=50%>


A Powerfull shellcode loader written in Zig, featuring multiple injection techniques and anti-sandbox capabilities.

## Features

- **Multiple Injection Techniques**:
  - Local Thread 
  - Local Mapping
  - Remote Mapping
  - Remote Thread
  - Syscalls Local Mapping

- **Anti-Sandbox Protection**:
  - TPM Presence Check
  - Domain Join Check

- **Output Formats**:
  - XLL (Excel Add-in)
  - DLL

- **Advanced Features**:
  - Base64 Shellcode Encoding
  - Compile-time String Processing
  - Memory Protection Handling
  - Process Targeting

## Prerequisites

- Zig 0.13.0
- Python 3.x (for the web interface)
- Flask
