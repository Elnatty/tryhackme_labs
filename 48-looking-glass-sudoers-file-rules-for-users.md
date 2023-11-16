# 48 - Looking Glass (sudoer's file rules for users)

Room Link --> [https://tryhackme.com/room/lookingglass](https://tryhackme.com/room/lookingglass)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.153.216 -sV -p- -T5

# output
from port 22, 9000 - 13783 were open, all SSH services.
```
{% endcode %}

Connecting to any of the ports gives either a lower or higher message output.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# port 13783
┌──(dking㉿dking)-[~/Downloads]
└─$ ssh 10.10.201.49 -o 'StrictHostKeyChecking=no' -p 13783
Higher
Connection to 10.10.201.49 closed.


# port 9000
┌──(dking㉿dking)-[~/Downloads]
└─$ ssh 10.10.201.49 -o 'StrictHostKeyChecking=no' -p 9000 
Warning: Permanently added '[10.10.201.49]:9000' (RSA) to the list of known hosts.
Lower
Connection to 10.10.201.49 closed.
```
{% endcode %}

We need to find the right port. I just kept narrowing it down till i  found the right port. Scripting this could take longer since we'd hae to iterate through all the numbers in an arithmetic progression.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ ssh 10.10.201.49 -o 'StrictHostKeyChecking=no' -p 12091
Warning: Permanently added '[10.10.201.49]:12091' (RSA) to the list of known hosts.
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:	

```
{% endcode %}

Username: `Jabberwocky` .

Trying to decode the cipher text:

Using this [vigenere](https://www.boxentriq.com/code-breaking/vigenere-cipher) decoder site. I tried automatic decode, and found the right key.

<figure><img src=".gitbook/assets/image (355).png" alt=""><figcaption></figcaption></figure>

Then i used the generated key: `thealphabetcipher`&#x20;

```
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is bewareTheJabberwock
```

We get the secret: `bewareTheJabberwock`&#x20;

When we input the secret, the connection closed.

<figure><img src=".gitbook/assets/image (356).png" alt=""><figcaption></figcaption></figure>

### Initial Access

But when we tried the credential given via the default ssh port 22, we logged in successfully.

`jabberwock : InstantlyWillingDivideFetch`&#x20;

<figure><img src=".gitbook/assets/image (357).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Tweedledum

There is a `twasBrillig.sh` file in jabberwock home dir, which uses the `bash wall` cmd to send a broadcast message, calling on a `poem.txt` file in the same dir.&#x20;

<figure><img src=".gitbook/assets/image (359).png" alt=""><figcaption></figcaption></figure>

Meaning the `.sh` script is printing the poem as a broadcast message. When i checked cronjob there is a job run by `tweedledum` user at reboot executing that `.sh` file.

<figure><img src=".gitbook/assets/image (358).png" alt=""><figcaption></figcaption></figure>

To exploit this, we just edit the `.sh` file with a reverse shell, then on reboot we get a shell as the `tweedledum` user (setup nc listener to catch the shell).

And we got a shell as `tweedledum` user.

<figure><img src=".gitbook/assets/image (360).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Tweedledee

`sudo -l` . we can execute bash as tweedledee

<figure><img src=".gitbook/assets/image (361).png" alt=""><figcaption></figcaption></figure>

`sudo -u tweedledee /bin/bash` - and we are Tweedledee.

<figure><img src=".gitbook/assets/image (362).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to HumptyDumpty

There is a `humptydumpty.txt` file in Tweedledee home dir.

```
tweedledee@looking-glass:/home/tweedledee$ cat humptydumpty.txt
cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

I just paste them into cyberchef and convert from Hex.

<figure><img src=".gitbook/assets/image (19) (1).png" alt=""><figcaption></figcaption></figure>

`humptydumpty : zyxwvutsrqponmlk` .

`su humptydumpty` - and we are humptydumpty.

### Priv Esc to Alice

Although we don't have access to list anything in alice home dir, but we can see that Alice's `.ssh` folder is available, and we can also access the Private keys.

<figure><img src=".gitbook/assets/image (365).png" alt=""><figcaption></figcaption></figure>

Use the priv key to gain login ssh acct for Alice.

<figure><img src=".gitbook/assets/image (366).png" alt=""><figcaption></figcaption></figure>

### Priv Esc to Tryhackme

Running LinPEAS.sh we found an interesting sudoers file rule for alice.

<figure><img src=".gitbook/assets/image (367).png" alt=""><figcaption></figcaption></figure>

The following is the syntax used by the Sudoers files, which means alice can run /bin/bash as root, but only on the “ssalg-gnikool” host.

<figure><img src="https://i0.wp.com/steflan-security.com/wp-content/uploads/2021/07/image-365.png?w=800&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

The -h flag can be used to specify the host when executing commands with Sudo:

`sudo -h ssalg-gnikool -u root /bin/bash` - and we are root.

```bash
alice@looking-glass:/etc/sudoers.d$ cat alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
alice@looking-glass:/etc/sudoers.d$ sudo -h ssalg-gnikool -u root /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:/etc/sudoers.d# cd /root/
root@looking-glass:/root# ls 
passwords  passwords.sh  root.txt  the_end.txt
```

Done!

