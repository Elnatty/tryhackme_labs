# 12 - Wreath

Room Link --> [https://tryhackme.com/room/wreath](https://tryhackme.com/room/wreath)

**Wreath** is designed as a learning resource for beginners with a primary focus on:

* Pivoting
* Working with the Empire C2 (Command and Control) framework
* Simple Anti-Virus evasion techniques

The following topics will also be covered, albeit more briefly:

* Code Analysis (Python and PHP)
* Locating and modifying public exploits
* Simple webapp enumeration and exploitation
* Git Repository Analysis
* Simple Windows Post-Exploitation techniques
* CLI Firewall Administration (CentOS and Windows)
* Cross-Compilation techniques
* Coding wrapper programs
* Simple exfiltration techniques
* Formatting a pentest report

## <mark style="color:red;">Key Notes:</mark>

* There are three machines on the network
* There is at least one public facing webserver
* There is a self-hosted git server somewhere on the network
* The git server is internal, so Thomas may have pushed sensitive information into it
* There is a PC running on the network that has antivirus installed, meaning we can hazard a guess that this is likely to be Windows
* By the sounds of it this is likely to be the server variant of Windows, which might work in our favour.
* The (assumed) Windows PC cannot be accessed directly from the webserver

## <mark style="color:red;">Enumeration</mark>

### <mark style="color:green;">WebServer Enumeration</mark>

We perform an initial scan using nmap:

{% code overflow="wrap" lineNumbers="true" fullWidth="true" %}
```bash
sudo nmap 10.200.87.200 -O -p1-15000 -Pn -n -sV -T4 -vv -oN initial_scan

# results
PORT      STATE  SERVICE    REASON         VERSION
22/tcp    open   ssh        syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
80/tcp    open   http       syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
443/tcp   open   ssl/http   syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
9090/tcp  closed zeus-admin reset ttl 63
10000/tcp open   http       syn-ack ttl 63 MiniServ 1.890 (Webmin httpd)
[...redacted...]
```
{% endcode %}

Port 10000 seems interesting.

<figure><img src=".gitbook/assets/image (88).png" alt=""><figcaption><p><a href="https://thomaswreath.thm:10000/">https://thomaswreath.thm:10000/</a></p></figcaption></figure>

We looked it up in google **"MiniServ 1.890 (Webmin httpd)"** and found it's vulnerable to RCE with CVE details --> <mark style="color:orange;">**CVE-2019-15107**</mark>

<figure><img src=".gitbook/assets/image (87).png" alt=""><figcaption><p>Vuln WebPage</p></figcaption></figure>

## <mark style="color:red;">Exploitation</mark>

Info on WebMin RCE --> [here](https://webmin.com/security/#remote-command-execution-cve-2019-15231)

We Exploited this Vulnerability using this Exploit --> [here](https://github.com/MuirlandOracle/CVE-2019-15107)

We obtained a Psuedoshell as the "root" user.

```bash
./CVE-2019-15107.py 10.200.87.200
```

<figure><img src=".gitbook/assets/image (89).png" alt=""><figcaption><p>pwned</p></figcaption></figure>

## <mark style="color:red;">Persistence</mark>

We can copy the "id\_rsa" file located in the `/root/.ssh/id_rsa` dir to our kali machine for maintaining persistence.

```bash
ssh root@10.200.87.200 -i id_rsa
```

<figure><img src=".gitbook/assets/image (90).png" alt=""><figcaption><p>SSH connection</p></figcaption></figure>

## <mark style="color:red;">Pivoting</mark>

There are two main methods encompassed in this area of pentesting:

* Tunnelling/Proxying: Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be _tunnelled_ inside another protocol (e.g. SSH tunnelling), which can be useful for evading a basic Intrusion Detection System (IDS) or firewall.
* Port Forwarding: Creating a connection between a local port and a single port on a target, via a compromised host.

**A proxy** is good if we want to redirect lots of different kinds of traffic into our target network -- for example, with an nmap scan, or to access multiple ports on multiple different machines.

**Port Forwarding** tends to be faster and more reliable, but only allows us to access a single port (or a small range) on a target device. Which style of pivoting is more suitable will depend entirely on the layout of the network.

### <mark style="color:green;">Pivot Enumeration</mark>

There are five possible ways to enumerate a network through a compromised host:

1. Using material found on the machine. The hosts file or ARP cache, for example.
2. Using pre-installed tools (nmap, bash, powershell).
3. Using statically compiled tools (binary files like .exe, nmap), etc.
4. Using scripting techniques.
5. Using local tools through a proxy (last resort because very SLOW).

<details>

<summary>Basic Pivot Enumeration Checklist</summary>

* `arp -a` - \[linux/windows].
* `cat /etc/hosts` - \[linux].
* `C:\Windows\System32\drivers\etc\hosts` -DNS \[windows].
* `/etc/resolv.conf` - DNS \[linux].
* `ipconfig /all` \[windows] and `nmcli dev show` \[linux].

</details>

Here is a link to some static Binary files --> [here](https://github.com/andrew-d/static-binaries)

Compiled Port Scanner for windows in C# --> [here](https://github.com/MuirlandOracle/C-Sharp-Port-Scan)

Compiled Port Scanner for windows in C++ --> [here](https://github.com/MuirlandOracle/CPP-Port-Scanner)

{% hint style="warning" %}
It's worth noting as well that you may encounter hosts which have firewalls blocking ICMP pings (Windows boxes frequently do this, for example). This is likely to be less of a problem when pivoting, however, as these firewalls (by default) often only apply to external traffic, meaning that anything sent through a compromised host on the network should be safe. It's worth keeping in mind, however.

If you suspect that a host is active but is blocking ICMP ping requests, you could also check some common ports using a tool like netcat.
{% endhint %}

Ping Sweep in Bash to discover other local networks:

{% code overflow="wrap" lineNumbers="true" %}
```bash
# bash ping sweep.
for i in {1..254}; do (ping -c 1 10.200.87.${i} | grep "bytes from" &); done
```
{% endcode %}

Port scanning in bash can be done (ideally) entirely natively:

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Bear in mind that this will take a very long time, however!
for i in {1..65535}; do (echo > /dev/tcp/10.200.87.200/$i) >/dev/null 2>&1 && echo $i is open; done

# or for selected ports.
for i in {21 80 111 135 139 445 443 8080 3389}; do (echo > /dev/tcp/10.200.87.200/$i) >/dev/null 2>&1 && echo $i is open; done
```
{% endcode %}

### <mark style="color:green;">1 - Proxychains & Foxyproxy</mark>

When creating a proxy we open up a port on our own attacking machine which is linked to the compromised server, giving us access to the target network.

**Proxychains** is a command line tool which is activated by prepending the command `proxychains` to other commands. For example, to proxy netcat  through a proxy, you could use the command:\
`proxychains nc 172.16.0.10 23`

Notice that a proxy port was not specified in the above command. This is because proxychains reads its options from a config file. The master config file is located at `/etc/proxychains.conf`. This is where proxychains will look by default; however, it's actually the last location where proxychains will look. The locations (in order) are:

1. The current directory (i.e. `./proxychains.conf`)
2. `~/.proxychains/proxychains.conf`
3. `/etc/proxychains.conf`

This makes it extremely easy to configure proxychains for a specific assignment, without altering the master file. Simply execute: `cp /etc/proxychains.conf .`, then make any changes to the config file in a copy stored in your current directory. If you're likely to move directories a lot then you could instead place it in a `.proxychains` directory under your home directory, achieving the same results. If you happen to lose or destroy the original master copy of the proxychains config, a replacement can be downloaded from [here](https://raw.githubusercontent.com/haad/proxychains/master/src/proxychains.conf).

{% hint style="danger" %}
There is one other line in the Proxychains configuration that is worth paying attention to, specifically related to the Proxy DNS settings:\
![Screenshot showing the proxy\_dns line in the Proxychains config](https://assets.tryhackme.com/additional/wreath-network/3af17f6ddafc.png)

If performing an Nmap scan through proxychains, this option can cause the scan to hang and ultimately crash. Comment out the `proxy_dns` line using a hashtag (`#`) at the start of the line before performing a scan through the proxy!\
![Proxy\_DNS line commented out with a hashtag](https://assets.tryhackme.com/additional/wreath-network/557437aec525.png)
{% endhint %}

{% hint style="warning" %}
Other things to note when scanning through proxychains:

* You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packets (Ping requests) will also not work through the proxy, so use the  `-Pn`  switch to prevent Nmap from trying it.
* It will be _extremely_ slow. Try to only use Nmap through a proxy when using the NSE (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library).
{% endhint %}

#### <mark style="color:green;">Foxyproxy</mark>

FoxyProxy is a browser extension which is available for [Firefox](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-basic/) and [Chrome](https://chrome.google.com/webstore/detail/foxyproxy-basic/dookpfaalaaappcdneeahomimbllocnb). There are two versions of FoxyProxy available: Basic and Standard. Basic works perfectly for our purposes.

<figure><img src=".gitbook/assets/image (91).png" alt=""><figcaption><p>foxyproxy</p></figcaption></figure>

Once activated, all of your browser traffic will be redirected through the chosen port (so make sure the proxy is active!). Be aware that if the target network doesn't have internet access (like all TryHackMe boxes) then you will not be able to access the outside internet when the proxy is activated. Even in a real engagement, routing your general internet searches through a client's network is unwise anyway, so turning the proxy off (or using the routing features in FoxyProxy standard) for everything other than interaction with the target network is advised.

With the proxy activated, you can simply navigate to the target domain or IP in your browser and the proxy will take care of the rest!

### <mark style="color:red;">2 - SSH Tunneling & Port Forwarding</mark>

The first tool we'll be looking at is none other than the bog-standard SSH client with an OpenSSH server. Using these simple tools, it's possible to create both forward and reverse connections to make SSH "tunnels", allowing us to forward ports, and/or create proxies.

#### <mark style="color:green;">Forward Connections</mark>

Creating a forward (or "local") SSH tunnel can be done from our attacking box when we have SSH access to the target. As such, this technique is much more commonly used against Unix hosts. Linux servers, in particular, commonly have SSH active and open. That said, Microsoft (relatively) recently brought out their own implementation of the OpenSSH server, native to Windows, so this technique may begin to get more popular in this regard if the feature were to gain more traction.

There are two ways to create a forward SSH tunnel using the SSH client -- **port forwarding**, and **creating a proxy**.







































