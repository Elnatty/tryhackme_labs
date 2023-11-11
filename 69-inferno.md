# 69 - Inferno

Room Link --> [https://tryhackme.com/room/inferno](https://tryhackme.com/room/inferno)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
```
{% endcode %}

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.103.251/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error

/inferno
```
{% endcode %}

We have an authentication page

<figure><img src=".gitbook/assets/image (463).png" alt=""><figcaption></figcaption></figure>



































