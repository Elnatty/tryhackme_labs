# 46 - Break Out The Cage (steganography, vigenear cipher, python)

Room Link --> [https://tryhackme.com/room/breakoutthecage1](https://tryhackme.com/room/breakoutthecage1)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.74.166 -p- -sV -T4

Open ports are 21 FTP, 22 SSH and 80 HTTP
```
{% endcode %}

#### FTP enum

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

The file contains some base64 encoded text, after decoding it, i pasted it in this site

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Decode it using:





#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.74.166 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -b 404,404,500,403,502 -x txt,php,db,sql,html

/contracts            (Status: 301) [Size: 316] 
/html                 (Status: 301) [Size: 311] [--> http://10.10.74.166/html/]
/images               (Status: 301) [Size: 313] [--> http://10.10.74.166/images/]
/index.html           (Status: 200) [Size: 2453]
/index.html           (Status: 200) [Size: 2453]
/scripts
/auditions
```
{% endcode %}

Navigating to /aauditions we see a .mp3 file. Then run sonic-visualizer on it.

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We get the key for the Vigenear cipher. `namelesstwo`

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Site to [decode](https://www.boxentriq.com/code-breaking/vigenere-cipher)

```
Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
One. Revamp the website
Two. Put more quotes in script
Three. Buy bee pesticide
Four. Help him with acting lessons
Five. Teach Dad what "information security" is.

In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes
```

We get the pasword for Weston.

We can ssh in to his account.

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

`sudo -l` -  We can execute a cmd as root.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```
weston@national-treasure:~$ sudo /usr/bin/bees
                                                                               
Broadcast message from weston@national-treasure (pts/0) (Mon Oct 30 10:30:11 20
                                                                               
AHHHHHHH THEEEEE BEEEEESSSS!!!!!!!!

```

There is a file in thr `/opt` dir, after running pspy or linPEAS.

The content of /opt/.dads\_scripts/spread\_the\_quotes.py file:

```python
#!/usr/bin/env python
#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random
lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)
```

What this script does:

1. Reads the /opt/.dads\_scripts/.files/.quotes file and stores the lines in a list
2. Chooses a random quote from the list and assigns it to the “quote” variable
3. Runs the wall command with the quote variable concatenated to it

So we can assume that this script is sending those broadcast messages with the wall command. It is executed every few minutes, probably with a cron job. We do not have write access to this file, but we have write access to the file that contains the quotes. This means that if we edit the quotes file, we can influence the following line of the script:

```python
os.system("wall " + quote)
```

Copy

For example, if the quote file would only contain a single line:

```
; touch /tmp/test
```

Then the command that would be executed:

```
wall ; touch /tmp/test
```

The wall command would be executed without arguments, then touch would be executed as a separate command. This way we can essentially run arbitrary commands as the user cage.

Now We don't have write access to the `spread_the_quotes.py` file but we can write to the `.quotes` file.

1. Create a script file containing a bash reverse shell in /tmp
2. Add executable permission to the file
3. Modify the .quotes file, so it only contains 1 line that will start the reverse shell
4. Start a netcat listener and wait for the connection

<figure><img src="https://narancsblog.com/wp-content/uploads/2021/11/thm-breakoutthecage1-06-reverse-shell-as-cage-1024x201.png" alt=""><figcaption></figcaption></figure>

Now we have a shell as cage user. Checking the home directory we can find a file named Super\_Duper\_Checklist and a directory named email\_backup. The Super\_Duper\_Checklist file contains the user flag.

### PrivEsc to root

In the email\_backup directory we can find 3 emails. The third email contains a strange string, that looks like a ciphertext. It is also interesting that the word “face” is repeated many times.

{% code overflow="wrap" lineNumbers="true" %}
```markup
From - Cage@nationaltreasure.com
To - Weston@nationaltreasure.com
Hey Son
Buddy, Sean left a note on his desk with some really strange writing on it. I quickly wrote
down what it said. Could you look into it please? I think it could be something to do with his
account on here. I want to know what he's hiding from me... I might need a new agent. Pretty
sure he's out to get me. The note said:
ha************ph
The guy also seems obsessed with my face lately. He came him wearing a mask of my face...
was rather odd. Imagine wearing his ugly face.... I wouldnt be able to FACE that!!
hahahahahahahahahahahahahahahaahah get it Weston! FACE THAT!!!! hahahahahahahhaha
ahahahhahaha. Ahhh Face it... he's just odd.
Regards
The Legend - Cage
```
{% endcode %}

The online cipher identifier tools mentioned earlier were not able to identify the correct cipher. It is most likely because the text is too short. Can try with Vigenear and key is `face` .

We get root pssword.

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

`Su root` .

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Done !

