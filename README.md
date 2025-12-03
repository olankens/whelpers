<hr>

# <samp>OVERVIEW</samp>

Windows related helper PowerShell module.

<hr>

### Features

- Add to path
- Get file version
- Get asset from github
- Get asset from store
- Set audio volume
- Set desktop background
- Set developer mode
- Set display scaling
- Set hostname
- Set lock screen background
- Set power plan
- Set sleeping timeout
- Use activate office
- Use activate windows
- Use create shortcut
- Use expand archive
- Use reboot and reload
- Use reload system clock
- Use remove desktop
- Use update gsudo
- Use update nanazip
- Use update powershell
- …

<hr>

### Import Module

```powershell
$Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/src/Whelpers.psm1"
$Content = ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address)))
New-Module -Name "$Address" -ScriptBlock $Content -EA SI > $Null
```

<hr>
