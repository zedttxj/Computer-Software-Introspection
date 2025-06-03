## Acknowledgement
I finished all of these modules from **pwn.college**, but will only demonstrate few examples here. You can check my profile on the [website](https://pwn.college/hacker/1o1).
# Computer Software Introspection

This repository contains a collection of scripts, tools, and methodologies for performing low-level software introspection, reverse engineering, and syscall tracing.

## Tools and Techniques Covered:
- Tracing syscalls and memory operations.
- Analyzing registers and performing linear equations with registers.
- Performing bitwise operations, modulo operations, and stack manipulations.
- Using **GDB**, **ROPgadget**, **objdump**, and **Ghidra** for analysis and reverse engineering.

## Tools:
- **GDB Scripts**: Automate tracing syscalls and memory analysis.
- **ROPgadget**: Discover and analyze gadgets for ROP chains.
- **objdump**: Disassemble and analyze binary code.
- **Ghidra**: Reverse engineer code with advanced analysis tools.

## Examples:
- Sample programs demonstrating syscall tracing, stack manipulation, and more.

---

## Acknowledgement
I finished all of these modules from **pwn.college**, but will only demonstrate few examples here. You can check my profile on the [website].(https://pwn.college/hacker/1o1). If you need solutions for specific problems, please contact me. Original repo of this content is [here](https://github.com/zedttxj/Web-Security-Exploits/tree/main/Example-1)
# Web-Security-Exploits (Server Penetration Testing) - *[pwn.college](https://pwn.college/cse365-f2024/web-security/)*

This repository showcases a web security project I have worked on as part of my training and exploration of cybersecurity. This project demonstrate a range of skills and techniques, including exploiting vulnerabilities and performing attacks.

In this project, I focused on exploiting **Web-Security vulnerabilities** through various attacks such as **XSS (Cross-Site Scripting)** and **CSRF (Cross-Site Request Forgery)**. Here’s what I worked on:
- Manipulated **Python requests** for vulnerability testing.
- Used **netcat** for port listening to capture **HttpOnly cookies**.
- Performed **URL manipulation attacks** like **path traversal** and **shell command injections**.
- Employed **fake server** techniques (created in Python) to retrieve stolen cookies (including **HttpOnly cookies**).
- Extracted sensitive data, such as **usernames, passwords**, and **session cookies**, showcasing how attackers can exploit web applications and steal information.

# Optimized-Port-Scanning & MITM - *[pwn.college](https://pwn.college/cse365-f2024/intercepting-communication/)*
This project was centered around network penetration testing, with an emphasis on **port scanning** and **Man-in-the-Middle (MITM) attacks**. The focus was on **ARP poisoning** and network traffic interception. Here's what was involved:
- **Tools Used**: **tshark**, **tcpdump**, **scapy**, **ping**, **netcat**, **socket** programming.
- Developed an **optimized port-scanning** technique using **tshark** for packet analysis and **tcpdump** for background traffic capture, which helped identify open ports.
- Manipulated **Layer 2, 3, and 4 headers** with **scapy** and established a **TCP handshake**.
- Updated the **ARP table** using **ping** and used **netcat** and **socket programming** to send customized payloads.
- Successfully executed a **MITM attack** using **ARP poisoning** to intercept and manipulate traffic between two devices within the same collision domain.

## Key Skills Demonstrated:

- **Web security exploitation**: XSS, CSRF, session hijacking, command injection.
- **Network attacks**: Port scanning, ARP poisoning, MITM, traffic interception.
- **Tools & Techniques**: Python (requests, socket), netcat, scapy, tshark, tcpdump.
- Able to perform Socket programming in Assembly language

### Acknowledgements:
- pwn.college for providing the exercises and challenges.
