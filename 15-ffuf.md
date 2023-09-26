# 15 - ffuf

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://10.10.140.90/FUZZ -w /opt/SecLists/Discovery/Web-Content/big.txt

# outputs all the supported extensions for the website.
ffuf -u http://10.10.140.90/FUZZ -w /opt/SecLists/Discovery/Web-Content/web-extensions.txt

# include paths with .php or .txt extensions in the output.
ffuf -u http://10.10.140.90/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -e .php,.txt

# outputs directories.
ffuf -u http://10.10.140.90/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```
{% endcode %}

### Using Filters

{% code overflow="wrap" lineNumbers="true" %}
```bash
# filter all 403 statuscode out. we can use "," for multiple codes.
ffuf -u http://10.10.140.90/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403

# match more than one code, we use "mc". we can use "," for multiple codes.
ffuf -u http://10.10.140.90/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -mc 200

# you could encounter entries with a 200 status code with a response size of zero.
-fs 0

# filter with regex.
# We often see there are false positives with files beginning with a dot (eg. .htgroups,.php, etc.). They throw a 403 Forbidden error, however those files don't actually exist. It's tempting to use -fc 403 but this could hide valuable files we don't have access to yet. So instead we can use a regexp to match all files beginning with a dot.
ffuf -u http://10.10.140.90/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fr '/\..*'
```
{% endcode %}

### Fuzzing Parameters

What would you do when you find a page or API endpoint but don't know which parameters are accepted? You fuzz!

Discovering a vulnerable parameter could lead to file inclusion, path disclosure, XSS, SQL injection, or even command injection. Since ffuf allows you to put the keyword anywhere we can use it to fuzz for parameters.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# fuzzing for vulnerable parameters example: id etc..
fuf -u 'http://10.10.160.211/sqli-labs/Less-1/?FUZZ=1' -c -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fw 39

# same as previous cmd, with different wordlist. (-c for color).
ffuf -u 'http://10.10.160.211/sqli-labs/Less-1/?FUZZ=1' -c -w /opt/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fw 39 
```
{% endcode %}

Now that we found a parameter accepting integer values we'll start fuzzing values.

At this point, we could generate a wordlist and save a file containing integers. To cut out a step we can use `-w -` which tells ffuf to read a wordlist from [stdout](https://www.gnu.org/software/libc/manual/html\_node/Standard-Streams.html). This will allow us to generate a list of integers with a command of our choice then pipe the output to ffuf. Below is a list of 2 different ways to generate numbers 0 - 255.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# "-w -" reads wordlist from std input.
# using for loop in bash.
$ for i in {0..255}; do echo $i; done | ffuf -u 'http://10.10.160.211/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33

# using seq in bash.
$ seq 0 255 | ffuf -u 'http://10.10.160.211/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33
```
{% endcode %}

We can also use ffuf for wordlist-based brute-force attacks, for example, **trying passwords on an authentication page.**

{% code overflow="wrap" lineNumbers="true" %}
```bash
# ffuf password bruteforce.
# "X" http method, "-d" POST data, "H" header.
ffuf -u http://10.10.160.211/sqli-labs/Less-11/ -c -w /opt/SecLists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
```
{% endcode %}

### Finding vhosts and subdomains

ffuf may not be as efficient as specialized tools when it comes to subdomain enumeration but it's possible to do.

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
{% endcode %}

Some subdomains might not be resolvable by the DNS server you're using and are only resolvable from within the target's local network by their private DNS servers. So some virtual hosts (vhosts) may exist with private subdomains so the previous command doesn't find them. To try finding private subdomains we'll have to use the Host HTTP header as these requests might be accepted by the web server.\
Note: [virtual hosts](https://httpd.apache.org/docs/2.4/en/vhosts/examples.html) (vhosts) is the name used by Apache httpd but for Nginx the right term is [Server Blocks](https://www.nginx.com/resources/wiki/start/topics/examples/server\_blocks/).\
You could compare the results obtained with direct subdomain enumeration and with vhost enumeration:

{% code overflow="wrap" lineNumbers="true" %}
```bash
$ ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0
$ ffuf -u http://mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.mydomain.com' -fs 0
```
{% endcode %}

For example, it is possible that you can't find a sub-domain with direct subdomain enumeration (1st command) but that you can find it with vhost enumeration (2nd command).

Vhost enumeration technique shouldn't be discounted as it may lead to discovering content that wasn't meant to be accessed externally.

### Proxifying ffuf traffic

Whether it's for [network pivoting](https://blog.raw.pm/en/state-of-the-art-of-network-pivoting-in-2019/) or for using BurpSuite plugins you can send all the ffuf traffic through a web proxy (HTTP or SOCKS5).

`ffuf -u http://10.10.160.211/ -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -x http://127.0.0.1:8080`

It's also possible to send only matches to your proxy for replaying:

`ffuf -u http://10.10.160.211/ -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -replay-proxy http://127.0.0.1:8080`

This may be useful if you don't need all the traffic to traverse an upstream proxy and want to minimize resource usage or to avoid polluting your proxy history.

### Reviewing the options

As you start to use ffuf more, some options will prove to be very useful depending on your situation. For example, `-ic` allows you to ignore comments in wordlists that such as headers, copyright notes, comments, etc

{% code overflow="wrap" lineNumbers="true" %}
```bash
# ignore comments in wordlists.
ffuf -u http://10.10.160.211/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -fs 0
```
{% endcode %}

### Saving Output into files/format

{% code overflow="wrap" lineNumbers="true" %}
```bash
# "-of" output format, "-o" output filename.
ffuf -u http://10.10.160.211/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403 -of md -o out.md
```
{% endcode %}



