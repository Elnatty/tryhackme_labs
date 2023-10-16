# 23 - Team

Room Link --> [https://tryhackme.com/room/teamcw](https://tryhackme.com/room/teamcw)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n 10.10.86.30 -p- -T4 -sS --min-rate 10000 -vv

# outputs
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
{% endcode %}

I tried web enumeration with "ffuf", "gobuster"  but didn't find anything. Anonymous accesss to ftp also doesn't work.

I also tried `whatweb 10.10.86.30` and found a domain name. We can add to "/etc/hosts" file.

<figure><img src=".gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

Now using "dirsearch" `dirsearch -u http://team.thm -t 200 -x 403 -w /usr/share/dirb/wordlists/common.txt`&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
[09:41:37] 301 -  305B  - /assets  ->  http://team.thm/assets/
[09:41:56] 301 -  305B  - /images  ->  http://team.thm/images/
[09:41:56] 200 -    3KB - /index.html
[09:42:19] 200 -    5B  - /robots.txt
[09:42:19] 301 -  306B  - /scripts  ->  http://team.thm/scripts/
```
{% endcode %}

`robots.txt` - gave us a username `dale` .

I tried to bruteforce for ssh passwords with hydra but it didn't work.

Next thing to try is sub-domain enumeration using "Wfuzz".

`wfuzz -c --hw 977 -u http://team.thm -H "Host: FUZZ.team.thm" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` - and got a sub-domain `dev` , adding it to /etc/hosts file.

<figure><img src=".gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (191).png" alt=""><figcaption></figcaption></figure>

Clicking the link on the Webpage, we can see the request is passed with query parameter (?page=). Also the hint on the queestion says there may be some flaws here either Cmd injection or LFI. CMD injection didn't work, but LFI did.

```bash
http://dev.team.thm/script.php?page=/../../../../etc/passwd
```

<figure><img src=".gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

And we can view the /etc/passwd file. Am going to use Burpsuite for a cleaner output.

<figure><img src=".gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

We got the user text file.

We are now certain that the web application has a file inclusion vulnerability. With this vulnerability two things comes in mind:

1. We may have to use that LFI vulnerability to get remote code execution though various methods eg. remote file inclusion, php wrappers(expect://,php://input) code execution, log poisoning, leaked phpinfo file etc.
2. Utilize this vulnerability to read some sensitive files that will lead to us compromising the box.

First of all, we run Intruder(which is fuzzer build in to BurpSuite) with a wordlist to check for common files on Linux systems.

Will use the "SecList" wordlist.

<figure><img src=".gitbook/assets/image (195).png" alt=""><figcaption></figcaption></figure>

Forward the request to Intruder, we use the sniper attack, load the payload lists `/opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` , then start the attack.

<figure><img src=".gitbook/assets/image (196).png" alt=""><figcaption></figcaption></figure>

We got many files, but the one of interest is the "/etc/ssh/sshd\_config" which contains dale ssh private key.

<figure><img src=".gitbook/assets/image (197).png" alt=""><figcaption></figcaption></figure>

### Initial Access

Copy the key to a "id.rsa" file the chmod 600 id\_rsa, and use it to ssh to Dale account.

<figure><img src=".gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to User \[gyles]

Running `sudo -l` we can execute sudo cmds as "gyles" to execute this file: `/home/gyles/admin_checks` .

This script is vulnerable because it uses the `read -p` cmd and takes input from the user, meaning we can just input "/bin/bash" as input and we get access as "gyles" :)

`sudo -u gyles /home/gyles/admin_checks` .

<figure><img src=".gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

Since we are in the "admin" group, lets find all files we have access to.

`find / -type f -group admin -exec ls -l {} ; 2>/dev/null`&#x20;

I got one file: --> `/usr/local/bin/main_backup.sh` . Its a cronjob that runs every minutes.

So i added a bash on-liner reverse shell, setup nc and waited, and got root shell.

<figure><img src=".gitbook/assets/image (200).png" alt=""><figcaption></figcaption></figure>

Done.

