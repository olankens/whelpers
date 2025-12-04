<div align="center">
<img src=".assets/icon.svg" height="128">
<h1><samp>WHELPERS</samp></h1>
<p>Windows related helper PowerShell module for automation purposes.</p>
</div>

<hr>

### Key Features

- Add to PATH
- Get file version
- Get asset from GitHub
- Get application from Microsoft Store
- Set audio volume
- Set desktop background
- Set developer mode
- Set display scaling
- Set hostname
- Set lock screen background
- Set power plan
- Set sleeping timeout
- Use active Office
- Use activate Windows
- Use create shortcut
- Use expand archive
- Use reboot and reload
- Use reload system clock
- Use remove desktop
- Use update gsudo
- Use update NanaZip
- Use update PowerShell
- …

<hr>

### Import Module

```powershell
$Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/src/Whelpers.psm1"
$Content = ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address)))
New-Module -Name "$Address" -ScriptBlock $Content -EA SI > $Null
```
