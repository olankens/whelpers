# OVERVIEW

<p><img src="https://lipsum.app/1280x640/202020/fff" width="100%"></p>

Windows related helper PowerShell module for automation purposes. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean fringilla dolor ac lorem tincidunt, ac dictum nunc iaculis. Proin aliquet urna vitae ullamcorper fringilla. Pellentesque nec porttitor risus, id condimentum dui. Fusce vehicula congue convallis. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; In sit amet orci sollicitudin, mattis mi ac, tempor lacus. Cras augue orci, euismod et turpis ut, vehicula hendrerit orci.

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
- Use active Windows
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

# GUIDANCE

### Import Module

```powershell
$Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/src/Whelpers.psm1"
$Content = ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address)))
New-Module -Name "$Address" -ScriptBlock $Content -EA SI > $Null
```
