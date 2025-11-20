Function Add-ToPath {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Payload,
        [Parameter(Mandatory = $True)] [ValidateSet("Machine", "Process", "User")] [String] $Section
    )

    If (-Not (Test-Path "$Payload")) { Return }
    $Pattern = "^$([Regex]::Escape($Payload))\\?"
    If ($Section -Ne "Process" ) {
        $OldPath = [Environment]::GetEnvironmentVariable("PATH", "$Section")
        $OldPath = $OldPath -Split ";" | Where-Object { $_ -NotMatch "$Pattern" }
        $NewPath = ($OldPath + $Payload) -Join ";"
        Invoke-Gsudo {
            [Environment]::SetEnvironmentVariable("PATH", "$Using:NewPath", "$Using:Section")
        }
    }
    $OldPath = $Env:Path -Split ";" | Where-Object { $_ -NotMatch "$Pattern" }
    $NewPath = ($OldPath + $Payload) -Join ";" ; $Env:Path = $NewPath -Join ";"

}

Function Get-FileVersion {

    Param (
        # Has to accept an empty string, so mandatory has to be false
        [Parameter(Mandatory = $False)] [String] $Payload
    )

    If ([String]::IsNullOrWhiteSpace($Payload)) { Return "0.0" }
    $Version = Try { $(powershell -Command "(Get-Package '${Payload}' -EA SI).Version") } Catch { $Null }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { (Get-AppxPackage "$Payload" -EA SI).Version } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { (Get-Command "$Payload" -EA SI).Version } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { (Get-Item "$Payload" -EA SI).VersionInfo.FileVersion } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { Invoke-Expression "& `"$Payload`" --version" -EA SI } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = "0.0" }
    Return [Regex]::Match($Version, "[\d.]+").Value.TrimEnd(".") -Replace "^[^.]+$", "$&.0"

}

Function Get-FromGithub {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Payload,
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Pattern
    )

    $Results = (Invoke-WebRequest "$Payload" | ConvertFrom-Json).assets
    $Address = $Results | Where-Object { $_.browser_download_url -Like "$Pattern" } | Select-Object -ExpandProperty browser_download_url
    $Fetched = Join-Path "$([IO.Path]::GetTempPath())" "$(Split-Path "$Address" -Leaf)"
    (New-Object Net.WebClient).DownloadFile("$Address", "$Fetched")
    Return "$Fetched"

}

Function Get-FromMicrosoftStore {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Payload
    )

    $Results = (Invoke-WebRequest "https://api.github.com/repos/mjishnu/alt-app-installer-cli/releases/latest" | ConvertFrom-Json).assets
    $Address = $Results | Where-Object { $_.browser_download_url -Like "*.exe" } | Select-Object -ExpandProperty browser_download_url
    $Fetched = Join-Path "$([IO.Path]::GetTempPath())" "$(Split-Path "$Address" -Leaf)"
    (New-Object Net.WebClient).DownloadFile("$Address", "$Fetched")
    $Deposit = Join-Path "$([IO.Path]::GetTempPath())" "downloads"
    Remove-Item -Path "$Deposit" -Recurse -Force -EA SI
    $ProgressPreference = "SilentlyContinue"
    Start-Process "$Fetched" "`"$Payload`" -d" -WindowStyle Minimized -Wait -WorkingDirectory "$([IO.Path]::GetTempPath())"
    $Element = (Get-ChildItem -Path "$Deposit" -File | Select-Object -First 1).FullName
    Return "$Element"

}

Function Set-AudioVolume {

    Param (
        [Parameter(Mandatory = $True)] [Int] $Payload
    )

    $Wscript = New-Object -ComObject WScript.Shell
    1..50 | ForEach-Object { $Wscript.SendKeys([Char]174) }
    If ($Payload -Ne 0) { 1..$($Payload / 2) | ForEach-Object { $Wscript.SendKeys([Char]175) } }

}

Function Set-DesktopBackground {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Picture
    )

    If (-Not (Test-Path "$Picture")) { Return }
    $Content += 'using System.Runtime.InteropServices;'
    $Content += 'public static class BackgroundChanger'
    $Content += '{'
    $Content += '   public const int SetDesktopWallpaper = 20;'
    $Content += '   public const int UpdateIniFile = 0x01;'
    $Content += '   public const int SendWinIniChange = 0x02;'
    $Content += '   [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]'
    $Content += '   private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);'
    $Content += '   public static void SetBackground(string path)'
    $Content += '   {'
    $Content += '       SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);'
    $Content += '   }'
    $Content += '}'
    Try { Add-Type -TypeDefinition $Content -EA SI } Catch {}
    [BackgroundChanger]::SetBackground($Picture)

}

Function Set-DeveloperMode {

    Param (
        [Parameter(Mandatory = $True)] [Bool] $Enabled
    )

    Invoke-Gsudo {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name AllowDevelopmentWithoutDevLicense -Value $(If ($Using:Enabled) { 1 } Else { 0 }) -Force -EA SI | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name AllowDevelopmentWithoutDevLicense -Value $(If ($Using:Enabled) { 1 } Else { 0 }) -EA SI | Out-Null
    }
    
}

Function Set-DisplayScaling {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [Int] $Scaling
    )

    $Content += '[DllImport("user32.dll", EntryPoint = "SystemParametersInfo")]'
    $Content += 'public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, uint pvParam, uint fWinIni);'
    $ApiCall = Add-Type -MemberDefinition "$($Content | Out-String)" -Name WinAPICall -Namespace SystemParamInfo -PassThru
    $ApiCall::SystemParametersInfo(0x009F, $Scaling, $Null, 1) | Out-Null

}

Function Set-Hostname {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Payload
    )

    If ((Hostname) -Ne "$Payload") {
        Invoke-Gsudo { Rename-Computer -NewName "$Using:Payload" -EA SI *> $Null }
    }

}

Function Set-LockscreenBackground {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Picture
    )

    If (-Not (Test-Path "$Picture")) { Return }
    $KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty "$KeyPath" "SubscribedContent-338387Enabled" -Value "0"
    $KeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    Invoke-Gsudo {
        New-Item "$Using:KeyPath" -Force -EA SI | Out-Null
        New-ItemProperty "$Using:KeyPath" "LockScreenImageStatus" -Value "1" -Force | Out-Null
        New-ItemProperty "$Using:KeyPath" "LockScreenImagePath" -Value "$Using:Picture" -Force | Out-Null
        New-ItemProperty "$Using:KeyPath" "LockScreenImageUrl" -Value "$Using:Picture" -Force | Out-Null
    }

}

Function Set-PowerPlan {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Payload
    )

    $Program = "C:\Windows\System32\powercfg.exe"
    $Picking = (& "$Program" /l | ForEach-Object { If ($_.Contains("($Payload")) { $_.Split()[3] } })
    If ([String]::IsNullOrEmpty("$Picking") -And $Payload -Eq "Ultra") { Return }
    If ([String]::IsNullOrEmpty("$Picking")) { & "$Program" /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 *> $Null }
    $Picking = (& "$Program" /l | ForEach-Object { If ($_.Contains("($Payload")) { $_.Split()[3] } })
    & "$Program" /s "$Picking"
    If ($Payload -Eq "Ultimate") {
        $Desktop = $Null -Eq (Get-WmiObject Win32_SystemEnclosure -ComputerName "localhost" | Where-Object ChassisTypes -In "{9}", "{10}", "{14}")
        $Desktop = $Desktop -Or $Null -Eq (Get-WmiObject Win32_Battery -ComputerName "localhost")
        If (-Not $Desktop) { & "$Program" /setacvalueindex $Picking sub_buttons lidaction 000 }
    }

}

Function Set-Sleeping {

    Param (
        [Parameter(Mandatory = $True)] [Bool] $Enabled
    )

    $Content += '[DllImport("kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]'
    $Content += 'public static extern void SetThreadExecutionState(uint esFlags);'
    $Handler = Add-Type -MemberDefinition "$($Content | Out-String)" -Name System -Namespace Win32 -PassThru
    $Payload = If ($Enabled) { [Uint32]"0x80000000" } Else { [Uint32]"0x80000000" -Bor [Uint32]"0x00000002" }
    $Handler::SetThreadExecutionState($Payload)

}

Function Set-Uac {

    Param (
        [Parameter(Mandatory = $True)] [Bool] $Enabled
    )

    $Content = @(
        '$KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"'
        "Set-ItemProperty -Path `"$KeyPath`" -Name ConsentPromptBehaviorAdmin -Value $(If ($Enabled) { 5 } Else { 0 })"
        "Set-ItemProperty -Path `"$KeyPath`" -Name PromptOnSecureDesktop -Value $(If ($Enabled) { 1 } Else { 0 })"
    )
    $Created = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(), "ps1")
    [IO.File]::WriteAllLines("$Created", $Content)
    Try { Start-Process "powershell" "-ep bypass -file `"$Created`"" -Verb RunAs -WindowStyle Hidden -Wait } Catch { }
    Remove-Item "$Created" -Force

}

Function Use-ActiveOffice {

    Invoke-Gsudo { & ([ScriptBlock]::Create((Invoke-RestMethod "https://get.activated.win"))) /OHOOK /S }

}

Function Use-ActiveWindows {

    $Content = (Write-Output ((cscript /nologo "C:\Windows\System32\slmgr.vbs" /xpr) -Join ""))
    If (-Not $Content.Contains("permanently activated")) {
        Invoke-Gsudo { & ([ScriptBlock]::Create((Invoke-RestMethod "https://get.activated.win"))) /HWID /S }
    }

}

Function Use-CreateShortcut {

    Param (
        [String] $LnkFile,
        [String] $Starter,
        [String] $ArgList,
        [String] $Message,
        [String] $Picture,
        [String] $WorkDir,
        [Switch] $AsAdmin
    )

    $Wscript = New-Object -ComObject WScript.Shell
    $Element = $Wscript.CreateShortcut("$LnkFile")
    If ($Starter) { $Element.TargetPath = "$Starter" }
    If ($ArgList) { $Element.Arguments = "$ArgList" }
    If ($Message) { $Element.Description = "$Message" }
    $Element.IconLocation = If ($Picture -And (Test-Path "$Picture")) { "$Picture" } Else { "$Starter" }
    $Element.WorkingDirectory = If ($WorkDir -And (Test-Path "$WorkDir")) { "$WorkDir" } Else { Split-Path "$Starter" }
    $Element.Save()
    If ($AsAdmin) {
        $Content = [IO.File]::ReadAllBytes("$LnkFile")
        $Content[0x15] = $Content[0x15] -Bor 0x20
        [IO.File]::WriteAllBytes("$LnkFile", $Content)
    }

}

Function Use-ExpandArchive {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Archive,
        [String] $Deposit,
        [String] $Secrets
    )

    If (-Not (Test-Path "$Env:LocalAppData\Microsoft\WindowsApps\7z.exe")) { Use-UpdateNanazip }
    If (-Not $Deposit) { $Deposit = [IO.Directory]::CreateDirectory("$Env:Temp\$([Guid]::NewGuid().Guid)").FullName }
    If (-Not (Test-Path "$Deposit")) { New-Item "$Deposit" -ItemType Directory -EA SI }
    & "$Env:LocalAppData\Microsoft\WindowsApps\7z.exe" x "$Archive" -o"$Deposit" -p"$Secrets" -y -bso0 -bsp0
    Return "$Deposit"

}

Function Use-RebootReload {

    $Current = (Get-PSCallStack | Where-Object { $_.ScriptName -Like "*.ps1" } | Select-Object -Last 1).ScriptName
    If ($Null -Ne $Current) {
        $Heading = (Get-Item "$Current").BaseName.ToUpper()
        If (-Not (Test-Path (Get-Item "$Env:ProgramFiles\PowerShell\*\pwsh.exe" -EA SI).FullName)) { Use-UpdatePowershell }
        # Windows Terminal is not installed on Windows LTSC IoT Enterprise
        # $Program = "$Env:LocalAppData\Microsoft\WindowsApps\wt.exe"
        # $Command = "$Program --title $Heading pwsh -ep bypass -noexit -nologo -file $Current"
        $Program = (Get-Item "$Env:ProgramFiles\PowerShell\*\pwsh.exe" -EA SI).FullName
        $Command = "$Program -ep bypass -noexit -nologo -file $Current"
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        New-ItemProperty "$RegPath" "$Heading" -Value "$Command" | Out-Null
        Invoke-Gsudo { Get-LocalUser -Name "$Env:Username" | Set-LocalUser -Password ([SecureString]::New()) }
        Set-Uac -Enabled $False
        Start-Sleep 4 ; Restart-Computer -Force ; Start-Sleep 2
    }

}

Function Use-ReloadClock {

    Invoke-Gsudo {
        Start-Process "w32tm" "/unregister" -WindowStyle Hidden -Wait
        Start-Process "w32tm" "/register" -WindowStyle Hidden -Wait
        Start-Process "net" "start w32time" -WindowStyle Hidden -Wait
        Start-Process "w32tm" "/resync /force" -WindowStyle Hidden -Wait
    }

}

Function Use-RemoveDesktop {

    Param (
        [Parameter(Mandatory = $True)] [ValidateNotNullOrEmpty()] [String] $Pattern
    )

    Start-Sleep -Seconds 4
    Remove-Item -Path "$Env:Public\Desktop\$Pattern"
    Remove-Item -Path "$Env:UserProfile\Desktop\$Pattern"

}

Function Use-UpdateGsudo {

    $Current = Get-FileVersion "*gsudo*"
    $Present = $Current -Ne "0.0"
    $Address = "https://api.github.com/repos/gerardog/gsudo/releases/latest"
    $Version = [Regex]::Match((Invoke-WebRequest "$Address" | ConvertFrom-Json).tag_name , "[\d.]+").Value
    $Updated = [Version] "$Current" -Ge [Version] "$Version"

    Try {
        If (-Not $Updated) {
            $Results = (Invoke-WebRequest "$Address" | ConvertFrom-Json).assets
            $Pattern = If ($Env:PROCESSOR_ARCHITECTURE -Match "^ARM") { "*arm64*msi" } Else { "*x64*msi" }
            $Address = $Results.Where( { $_.browser_download_url -Like "$Pattern" } ).browser_download_url
            $Fetched = Join-Path "$([IO.Path]::GetTempPath())" "$(Split-Path "$Address" -Leaf)"
            (New-Object Net.WebClient).DownloadFile("$Address", "$Fetched")
            If (-Not $Present) { Start-Process "msiexec" "/i `"$Fetched`" /qn" -Verb RunAs -Wait }
            Else { Invoke-Gsudo { msiexec /i "$Using:Fetched" /qn } }
            Start-Sleep 4
        }
        Add-ToPath "$Env:ProgramFiles\gsudo\Current" "Process"
        Return $True
    }
    Catch {
        Return $False
    }

}

Function Use-UpdateNanazip {

    $Current = Get-FileVersion "*nanazip*"
    $Address = "https://api.github.com/repos/m2team/nanazip/releases/latest"
    $Version = [Regex]::Match((Invoke-WebRequest "$Address" | ConvertFrom-Json).tag_name , "[\d.]+").Value
    $Updated = [Version] "$Current" -Ge [Version] "$Version"

    If (-Not $Updated) {
        $Results = (Invoke-WebRequest "$Address" | ConvertFrom-Json).assets
        $Address = $Results.Where( { $_.browser_download_url -Like "*.msixbundle" } ).browser_download_url
        $Fetched = Join-Path "$([System.IO.Path]::GetTempPath())" "$(Split-Path "$Address" -Leaf)"
        (New-Object Net.WebClient).DownloadFile("$Address", "$Fetched")
        Invoke-Gsudo {
            $ProgressPreference = "SilentlyContinue"
            Add-AppxPackage -Path "$Using:Fetched" -DeferRegistrationWhenPackagesAreInUse -ForceUpdateFromAnyVersion
        }
    }

}

Function Use-UpdatePowershell {

    $Starter = (Get-Item "$Env:ProgramFiles\PowerShell\*\pwsh.exe" -EA SI).FullName
    $Current = Get-FileVersion "$Starter"
    $Address = "https://api.github.com/repos/powershell/powershell/releases/latest"
    $Version = [Regex]::Match((Invoke-WebRequest "$Address" | ConvertFrom-Json).tag_name , "[\d.]+").Value
    $Updated = [Version] "$Current" -Ge [Version] "$Version"

    If (-Not $Updated) {
        Invoke-Gsudo {
            $ProgressPreference = "SilentlyContinue"
            Invoke-Expression "& { $(Invoke-RestMethod "https://aka.ms/install-powershell.ps1") } -UseMSI -Quiet" *> $Null
        }
    }

    If ($PSVersionTable.PSVersion -Lt [Version] "7.0") { Use-RebootReload }

}

Function Use-UpdateWrapper {

    Param (
        [Parameter(Mandatory = $True)] [String] $Heading,
        [Parameter(Mandatory = $True)] [String] $Country,
        [Parameter(Mandatory = $True)] [String] $Machine,
        [Parameter(Mandatory = $True)] [ScriptBlock[]] $Members,
        [String] $Outputs = "$Env:Temp\$((Get-Date).ToString("yyyy-MM-dd")).LOG"
    )

    $Current = (Get-PSCallStack | Where-Object { $_.ScriptName -Like "*.ps1" } | Select-Object -Last 1).ScriptName
    If ($Null -Ne $Current) { $Host.UI.RawUI.WindowTitle = (Get-Item "$Current").BaseName.ToUpper() }

    Clear-Host ; $ProgressPreference = "SilentlyContinue" ; $WarningPreference = "SilentlyContinue"
    $Heading = (($Heading -Split "`n" | ForEach-Object { $_.Trim() }) -Join "`n").TrimStart()
    Write-Host "$Heading" -ForegroundColor Green -NoNewLine

    $Loading = "`nTHE UPDATING PROCESS HAS LAUNCHED"
    $Failure = "`rTHE UPDATING PROCESS WAS CANCELED"
    Write-Host "$Loading" -FO DarkYellow -NoNewline
    Set-Uac -Enabled $False ; Set-Sleeping -Enabled $False ; Set-PowerPlan -Payload "Ultimate"
    $Correct = (Use-UpdateGsudo) -And ! (gsudo cache on -d -1 2>&1).ToString().Contains("Error")
    If (-Not $Correct) { Write-Host "$Failure`n" -FO Red ; Exit }
    Use-UpdatePowershell ; Set-Uac -Enabled $True

    Set-TimeZone -Name "$Country" ; Use-ReloadClock
    Set-Hostname -Payload "$Machine"

    $Bigness = ($Heading -Split "`n" | ForEach-Object { $_.Length }) | Measure-Object -Maximum | ForEach-Object Maximum
    $Bigness = ($Bigness - 19) * -1
    $Shaping = "`r{0,$Bigness}{1,-3}{2,-5}{3,-3}{4,-8}"
    Write-Host ("$Shaping" -F "FUNCTION", " ", "ITEMS", " ", "DURATION")
    $Minimum = 0 ; $Maximum = $Members.Count
    Foreach ($Element In $Members) {
        $Minimum++ ; $Started = Get-Date
        $Running = $Element.ToString().Trim().Split(' ')[0].ToUpper()
        $Shaping = "`n{0,$Bigness}{1,-3}{2,-5}{3,-3}{4,-8}"
        $Advance = "$("{0:d2}" -F [Int] $Minimum)/$("{0:d2}" -F [Int] $Maximum)"
        $Loading = "$Shaping" -F "$Running", "", "$Advance", "", "--:--:--"
        Write-Host "$Loading" -ForegroundColor DarkYellow -NoNewline
        Try {
            & $Element *>> "$Outputs"
            $Elapsed = "{0:hh}:{0:mm}:{0:ss}" -F ($(Get-Date) - $Started)
            $Shaping = "`r{0,$Bigness}{1,-3}{2,-5}{3,-3}{4,-8}"
            $Success = "$Shaping" -F "$Running", "", "$Advance", "", "$Elapsed"
            Write-Host "$Success" -ForegroundColor Green -NoNewLine
        }
        Catch {
            $Elapsed = "{0:hh}:{0:mm}:{0:ss}" -F ($(Get-Date) - $Started)
            $Shaping = "`r{0,$Bigness}{1,-3}{2,-5}{3,-3}{4,-8}"
            $Failure = "$Shaping" -F "$Running", "", "$Advance", "", "$Elapsed"
            Write-Host "$Failure" -ForegroundColor Red -NoNewLine
        }
    }

    Set-Sleeping -Enabled $True ; gsudo -k *> $Null
    Write-Host "`n"

}