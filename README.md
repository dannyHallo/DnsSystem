# Simple DNS System

This repository contains the source code and data files for a simple DNS system that consists of four modules: client, local DNS server, DNS server, and Wireshark parsing. The system is designed and implemented using C programming language and socket programming techniques. The system communicates using UDP and TCP protocols and follows the DNS message format and data structures.

## Directory Structure

The repository has the following directory structure:

- .vscode: This directory contains the configuration files for Visual Studio Code, such as c_cpp_properties.json and settings.json.
- records: This directory contains the database files for the DNS server module, such as rr2.txt, rr3.txt, rr4.txt, rr5.txt, rr6.txt, rr7.txt, and rr8.txt. Each file contains a sequence of resource records separated by newlines. Each resource record has five fields: NAME, TTL, CLASS, TYPE, and RDATA.
- sh: This directory contains the shell scripts for running the system on Linux, such as run.sh and kill.sh.
- .gitattributes: This file specifies the attributes of the files in the repository for Git operations.
- DNSClient.c: This file contains the source code for the client module. It takes the user input from the command line interface and sends a DNS request message to the local DNS server module via UDP protocol. It also receives a DNS response message from the local DNS server module and shows the resolution result or error message to the user.
- DNSServer.c: This file contains the source code for the DNS server module. It receives a DNS request message from the local DNS server module via TCP protocol and answers it from its database. It also sends back a DNS response message with either an IP address, a next hop server's IP address and a referral code, or an empty packet and an error code to the local DNS server module.
- global.h: This file contains the header file for the system. It defines the constants, macros, data structures, and function prototypes used by all modules.
- LocalDNSServer.c: This file contains the source code for the local DNS server module. It receives a DNS request message from the client module or other DNS server modules via UDP or TCP protocol. It also looks for matching domain name resolution results in its cache or starts an iterative resolution request to another DNS server module via TCP protocol. It then sends back a DNS response message with either an IP address, an error code, or an empty packet to the requesting module.
- test.c: This file contains some test code for debugging purposes.

## Usage

To run the system on Linux, follow these steps:

1. Clone or download this repository to your local machine.
2. Open a terminal window and navigate to the repository directory.
3. Run `sh run.sh` to compile and execute all modules in separate processes.
4. Open another terminal window and navigate to the repository directory.
5. Run `./client <domain name> <query type>` to send a query to the local DNS server module. For example, `./client www.github.com A`.
6. Wait for the response from the local DNS server module and check the result or error message on the terminal window.
7. To stop all modules, run `sh kill.sh` on another terminal window.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
