# 33 - NAX

Room Link --> [https://tryhackme.com/room/nax](https://tryhackme.com/room/nax)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n -p- -T5 -sS -vv 10.10.131.31

PORT      STATE    SERVICE        REASON
22/tcp    open     ssh            syn-ack ttl 63
25/tcp    open     smtp           syn-ack ttl 63
80/tcp    open     http           syn-ack ttl 63
389/tcp   open     ldap           syn-ack ttl 63
443/tcp   open     https          syn-ack ttl 63
5667/tcp  open     unknown        syn-ack ttl 63
```
{% endcode %}

Navigating to the webpage:

<figure><img src=".gitbook/assets/image (242).png" alt=""><figcaption><p>elements</p></figcaption></figure>

So i pasted the strange "elements" in google and saw many results relating to the "Periodic Table of the Elements"

So looking them up

<figure><img src=".gitbook/assets/image (244).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
Ag - Hg - Ta - Sb - Po - Pd - Hg - Pt - Lr
47 80 73 51 84 46 80 78 103

# /PI3T.PNG
```
{% endcode %}

Pasting the Decimal values in cyberchef and got a .png file.

<figure><img src=".gitbook/assets/image (243).png" alt=""><figcaption></figcaption></figure>

Downloading the png file: http://10.10.131.31/PI3T.PNg

Running Exiftool on the image:

`exiftool PI3T.PNg` .

<figure><img src=".gitbook/assets/image (245).png" alt=""><figcaption></figcaption></figure>

We use an online tool: `npiet`&#x20;



























