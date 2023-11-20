# 56 - NerdHerd

Room Link --> [https://tryhackme.com/room/nerdherd](https://tryhackme.com/room/nerdherd)

### Enumertion

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ nmap -Pn -n -v 10.10.158.77 -p- -T5 -T4 -sV

PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           vsftpd 3.0.3
22/tcp    open     ssh           OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
139/tcp   open     netbios-ssn   Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open     netbios-ssn   Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
1337/tcp  open     http          Apache httpd 2.4.18 ((Ubuntu))
```
{% endcode %}

#### FTP enum

Connecting to FTP, there is a `youfoundme.png` image and a `hellon3rd.txt` file there.

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ cat hellon3rd.txt          
all you need is in the leet
```

#### Image analysis

`exiftool youfoundme.png` -&#x20;

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Googling the cipher `fijbxslz` and saw that is was a vigenere cipher. We need a key.

Viewing the webpage source code:

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*I0iY_VljiJhHm9CoN1Y7ug.png" alt="" height="189" width="700"><figcaption><p>page source</p></figcaption></figure>

Let’s see the **youtube** link:

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*2V2u4Jk5E9nBgWTZHjmADg.png" alt="" height="135" width="700"><figcaption><p>youtube</p></figcaption></figure>

It’s a song called “**Surfin Bird**”. Look at its lyrics:

<figure><img src="https://miro.medium.com/v2/resize:fit:434/1*9TaA67bm_NH4bzKlnSQqKA.png" alt="" height="696" width="505"><figcaption><p>lyrics</p></figcaption></figure>

The word “**bird**” is repeated many times. Maybe it’s the key to decrypt the cipher text above? Let’s try:

<figure><img src="https://miro.medium.com/v2/resize:fit:539/1*Ft7OJWCp2UtCj8IH7cW0Zw.png" alt="" height="451" width="627"><figcaption><p>decode cipher</p></figcaption></figure>

YES it’s! But it’s not fully decoded. What about **birdistheworld?**

<figure><img src="https://miro.medium.com/v2/resize:fit:485/1*x5w8-V5nKZOEUbREz_CMtQ.png" alt="" height="455" width="564"><figcaption><p>decode</p></figcaption></figure>

Finally it’s fully decoded! Now I’ve got another hint `easypass` .

#### SMB enum

We don't have access to any of the file shares.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Lets try enum4linux:

```
┌──(dking㉿dking)-[~/Downloads]
└─$ enum4linux 10.10.158.77
```

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

A username `chuk` .

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.158.77:1337 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error

/admin
```
{% endcode %}

Going to `/admin` and got some encoded ciphers.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```bash
Y2liYXJ0b3dza2k= : aGVoZWdvdTwdasddHlvdQ==
# decoded
cibartowski : hehegou<.jÇ].[ÝD
```

These are what we have:

```
Username: chuk

easypass
cibartowski
hehegou<.jÇ].[ÝD
```

I tried each combination for ssh, but didn't work, but `chuck : easypass` worked for SMB.

```bash
──(dking㉿dking)-[~/Downloads]
└─$ smbclient //10.10.158.77/nerdherd_classified -U chuck

# there is a secr3t.txt file in the share.

┌──(dking㉿dking)-[~/Downloads]
└─$ cat secr3t.txt     
Ssssh! don't tell this anyone because you deserved it this far:

	check out "/this1sn0tadirect0ry"

Sincerely,
	0xpr0N3rd
<3
```

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```
alright, enough with the games.

here, take my ssh creds:
	
	chuck : th1s41ntmypa5s
```

### Initial Access

SO we login via ssh..

### Priv Esc

I uploaded linpeas to the victim machine with Python3 and ran it. The only interesting result I got from it was the basic information at the beginning. The Linux version is maked as a possible privilege escalation factor.

<figure><img src="https://marcorei7.files.wordpress.com/2020/11/linpeas.png?w=1024" alt="Linpeas" height="75" width="1024"><figcaption></figcaption></figure>

It’s from 2016, which means it’s really old. Look on google for exploit and I found this [**link**](https://www.exploit-db.com/exploits/45010)**.** It’s written in C, and gcc is existed on the target machine:

<figure><img src="https://miro.medium.com/v2/resize:fit:303/1*8-vdqGGFIel-01vgrell4w.png" alt="" height="74" width="352"><figcaption><p>gcc</p></figcaption></figure>

Compile it `gcc exp.c exp` .

Then run it. `./exp` and got root.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Find the root.txt flag file.

`find / -iname 'root.txt' 2>/dev/null` .

It was in the `/opt` dir.

Bonus flag was in `.bash_history` .

Done!
