# <samp>OVERVIEW</samp>

Windows related helper PowerShell module.

<table>
  <tr align="center">
    <th><samp>AND</samp></th>
    <th><samp>IOS</samp></th>
    <th><samp>LIN</samp></th>
    <th><samp>MAC</samp></th>
    <th><samp>WIN</samp></th>
    <th><samp>WEB</samp></th>
  </tr>
  <tr align="center" height="50">
    <td width="9999">🟥</td>
    <td width="9999">🟥</td>
    <td width="9999">🟥</td>
    <td width="9999">🟥</td>
    <td width="9999">🟩</td>
    <td width="9999">🟥</td>
  </tr>
</table>

# <samp>GUIDANCE</samp>

### Import the Module

```powershell
$Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/src/Whelpers.psm1"
$Content = ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address)))
New-Module -Name "$Address" -ScriptBlock $Content -EA SI > $Null
```
