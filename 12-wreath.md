# 12 - Wreath

Room Link --> [https://tryhackme.com/room/wreath](https://tryhackme.com/room/wreath)

**Wreath** is designed as a learning resource for beginners with a primary focus on:

* Pivoting
* Working with the Empire C2 (Command and Control) framework
* Simple Anti-Virus evasion techniques

The following topics will also be covered, albeit more briefly:

* Code Analysis (Python and PHP)
* Locating and modifying public exploits
* Simple webapp enumeration and exploitation
* Git Repository Analysis
* Simple Windows Post-Exploitation techniques
* CLI Firewall Administration (CentOS and Windows)
* Cross-Compilation techniques
* Coding wrapper programs
* Simple exfiltration techniques
* Formatting a pentest report

## <mark style="color:red;">Key Notes:</mark>

* There are three machines on the network
* There is at least one public facing webserver
* There is a self-hosted git server somewhere on the network
* The git server is internal, so Thomas may have pushed sensitive information into it
* There is a PC running on the network that has antivirus installed, meaning we can hazard a guess that this is likely to be Windows
* By the sounds of it this is likely to be the server variant of Windows, which might work in our favour.
* The (assumed) Windows PC cannot be accessed directly from the webserver

## <mark style="color:red;">Enumeration</mark>

### <mark style="color:green;">WebServer Enumeration</mark>

\




























