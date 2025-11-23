<div align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset=".assets/icon-dark.svg">
        <img src=".assets/icon.svg" height="132">
    </picture>
    <h1><samp>WHELPERS</samp></h1>
    <p>Windows related helper PowerShell module.</p>
</div>

---

### Import Module

```powershell
$Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/src/Whelpers.psm1"
$Content = ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address)))
New-Module -Name "$Address" -ScriptBlock $Content -EA SI > $Null
```
