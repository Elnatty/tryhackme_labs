---
description: Python Pickles
---

# 4 - Peak Hill

Room Link: [https://tryhackme.com/room/peakhill](https://tryhackme.com/room/peakhill)

We start with an nmap scan.

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -sV -Pn -n -p- 10.10.2.255 --min-rate 10000 --open

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
7321/tcp open  swx?
```
{% endcode %}

We tried anonymous login to ftp and got 2 files:

* test.txt
* .creds

The .creds file contained binary data, we use cyberchef  with the "from Binary" recipe to decode the binary data. On downloading the output, it was a "Download.dat" file.

Turns out this was a Seriallized data, we can use the "Pickle Module" to "Deserialize" the data.

We  use the below python script to get the username and password.

{% code overflow="wrap" lineNumbers="true" %}
````python
```python
import pickle

with open("../Downloads/download.dat", "rb") as file:
    # Read the pickled data from the file
    pickle_data = file.read()

# Unpickle the data
creds = pickle.loads(pickle_data)

pass_str = ""
user_str = ""
password_list = []
username_list = []

for i,j in creds:
    if 'ssh_pass' in i:
        i = int(i[8:])
        password_list.append((i,j))
    else:
        i = int(i[8:])
        username_list.append((i,j))

password_list.sort()
for i,j in password_list:
    pass_str += j
username_list.sort()
for i,j in username_list:
    user_str += j

print(f"Username: {user_str}\nPassword: {pass_str}")
```
````
{% endcode %}

Login to SSH









