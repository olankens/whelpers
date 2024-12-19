# <samp>OVERVIEW</samp>

Windows related helper PowerShell module.

| <samp>AND</samp> | <samp>IOS</samp> | <samp>LIN</samp> | <samp>MAC</samp> | <samp>WIN</samp> | <samp>WEB</samp> |
| :-: | :-: | :-: | :-: | :-: | :-: |
| <br>🟥<br><br> | <br>🟥<br><br> | <br>🟥<br><br> | <br>🟥<br><br> | <br>🟩<br><br> | <br>🟥<br><br> |

# <samp>FEATURES</samp>

- Change desktop and lockscreen background
- Change power plan
- Change process, system and user path
- Change sound volume
- Change thread execution state
- Change uac configuration
- Create shortcut
- Extract any archive
- Reboot machine and relaunch the current script
- Update gsudo, nanazip and powershell
- ...

# <samp>GUIDANCE</samp>

### Import module

```powershell
$Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/Whelpers.psm1"
New-Module -Name "$Address" -ScriptBlock ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address))) -EA SI > $Null
```
