Function Enable-Office {
    
    Invoke-Gsudo { & ([ScriptBlock]::Create((Invoke-RestMethod "https://get.activated.win"))) /OHOOK /S }

}

Function Enable-Sleeping {

    $Content = @()
    $Content += '[DllImport("kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]'
    $Content += 'public static extern void SetThreadExecutionState(uint esFlags);'
    $Handler = Add-Type -MemberDefinition "$($Content | Out-String)" -Name System -Namespace Win32 -PassThru
    $Handler::SetThreadExecutionState([Uint32]"0x80000000") # ES_CONTINUOUS

}

Function Enable-Uac {

    $Content = @(
        '$KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"'
        'Set-ItemProperty -Path "$KeyPath" -Name ConsentPromptBehaviorAdmin -Value 5'
        'Set-ItemProperty -Path "$KeyPath" -Name PromptOnSecureDesktop -Value 1'
    ) -Join "`n"
    $Created = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(), "ps1")
    [IO.File]::WriteAllText("$Created", $Content)
    Try { Start-Process "powershell" "-ep bypass -file `"$Created`"" -Verb RunAs -WindowStyle Hidden -Wait } Catch { }
    Remove-Item "$Created" -Force

}

Function Enable-Windows {

    $Content = (Write-Output ((cscript /nologo "C:\Windows\System32\slmgr.vbs" /xpr) -Join ""))
    If (-Not $Content.Contains("permanently activated")) {
        Invoke-Gsudo { & ([ScriptBlock]::Create((Invoke-RestMethod "https://get.activated.win"))) /HWID /S }
    }

}

Function Expand-Version {

    Param (
        [String] $Payload
    )

    If ([String]::IsNullOrWhiteSpace($Payload)) { Return "0.0.0.0" }
    $Version = $(powershell -Command "(Get-Package `"$Payload`" -EA SI).Version")
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = (Get-AppxPackage "$Payload" -EA SI).Version }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { (Get-Command "$Payload" -EA SI).Version } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { (Get-Item "$Payload" -EA SI).VersionInfo.FileVersion } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = Try { Invoke-Expression "& `"$Payload`" --version" -EA SI } Catch { $Null } }
    If ([String]::IsNullOrWhiteSpace($Version)) { $Version = "0.0.0.0" }
    Return [Regex]::Match($Version, "[\d.]+").Value.TrimEnd(".") -Replace "^[^.]+$", "$&.0"

}

Function Invoke-Extract {

    Param (
        [String] $Archive,
        [String] $Deposit,
        [String] $Secrets
    )

    If (-Not (Test-Path "$Env:LocalAppData\Microsoft\WindowsApps\7z.exe")) { Update-Nanazip }
    If (-Not $Deposit) { $Deposit = [IO.Directory]::CreateDirectory("$Env:Temp\$([Guid]::NewGuid().Guid)").FullName }
    If (-Not (Test-Path "$Deposit")) { New-Item "$Deposit" -ItemType Directory -EA SI }
    & "$Env:LocalAppData\Microsoft\WindowsApps\7z.exe" x "$Archive" -o"$Deposit" -p"$Secrets" -y -bso0 -bsp0
    Return "$Deposit"

}

Function Invoke-Restart {

    $Current = $Script:MyInvocation.MyCommand.Path
    $Program = "$Env:LocalAppData\Microsoft\WindowsApps\wt.exe"
    $Heading = (Get-Item "$Current").BaseName.ToUpper()
    $Command = "$Program --title $Heading pwsh -ep bypass -noexit -nologo -file $Current"
    $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    If (-Not (Test-Path (Get-Item "$Env:ProgramFiles\PowerShell\*\pwsh.exe" -EA SI).FullName)) { Update-Powershell }
    New-ItemProperty "$RegPath" "$Heading" -Value "$Command" | Out-Null
    Invoke-Gsudo { Get-LocalUser -Name "$Env:Username" | Set-LocalUser -Password ([SecureString]::New()) }
    Remove-Uac
    Start-Sleep 4 ; Restart-Computer -Force ; Start-Sleep 2

}

Function Remove-Desktop {

    Param(
        [String] $Pattern
    )

    Remove-Item -Path "$Env:Public\Desktop\$Pattern"
    Remove-Item -Path "$Env:UserProfile\Desktop\$Pattern"

}

Function Remove-Sleeping {

    $Content = @()
    $Content += '[DllImport("kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]'
    $Content += 'public static extern void SetThreadExecutionState(uint esFlags);'
    $Handler = Add-Type -MemberDefinition "$($Content | Out-String)" -Name System -Namespace Win32 -PassThru
    $Handler::SetThreadExecutionState([uint32]"0x80000000" -Bor [uint32]"0x00000002") # ES_DISPLAY_REQUIRED

}

Function Remove-Uac {

    $Content = @(
        '$KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"'
        'Set-ItemProperty -Path "$KeyPath" -Name ConsentPromptBehaviorAdmin -Value 0'
        'Set-ItemProperty -Path "$KeyPath" -Name PromptOnSecureDesktop -Value 0'
    ) -Join "`n"
    $Created = [IO.Path]::ChangeExtension([IO.Path]::GetTempFileName(), "ps1")
    [IO.File]::WriteAllText("$Created", $Content)
    $Present = $(Expand-Version "*gsudo*") -Ne "0.0.0.0"
    If (-Not $Present) { Try { Start-Process "powershell" "-ep bypass -file `"$Created`"" -Verb RunAs -WindowStyle Hidden -Wait } Catch { } }
    Else { Invoke-Gsudo { Try { Start-Process "powershell" "-ep bypass -file `"$Using:Created`"" -WindowStyle Hidden -Wait } Catch { } } }
    Remove-Item "$Created" -Force

}

Function Rename-Computer {

    Param(
        [String] $Payload
    )

    If ([String]::IsNullOrWhiteSpace("$Payload")) { Return }
    If ((Hostname) -Ne "$Payload") {
        Invoke-Gsudo { Rename-Computer -NewName "$Using:Payload" -EA SI *> $Null }
    }

}

Function Update-Desktop {

    Param(
        [String] $Payload
    )

    If (-Not (Test-Path -Path "$Payload")) { return }
    $Content = @()
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
    $Content = $Content | Out-String
    Add-Type -TypeDefinition "$Content"
    [BackgroundChanger]::SetBackground($Payload)

}

Function Update-Gsudo {

    $Current = Expand-Version "*gsudo*"
    $Present = $Current -Ne "0.0.0.0"
    $Address = "https://api.github.com/repos/gerardog/gsudo/releases/latest"
    $Version = [Regex]::Match((Invoke-WebRequest "$Address" | ConvertFrom-Json).tag_name , "[\d.]+").Value
    $Updated = [Version] "$Current" -Ge [Version] "$Version"

    Try {
        If (-Not $Updated) {
            $Results = (Invoke-WebRequest "$Address" | ConvertFrom-Json).assets
            # $Address = $Results.Where( { $_.browser_download_url -Like "*x64*msi" } ).browser_download_url
            $Address = $Results.Where( { $_.browser_download_url -Like "*arm64*msi" } ).browser_download_url
            $Fetched = Join-Path "$([System.IO.Path]::GetTempPath())" "$(Split-Path "$Address" -Leaf)"
            (New-Object Net.WebClient).DownloadFile("$Address", "$Fetched")
            If (-Not $Present) { Start-Process "msiexec" "/i `"$Fetched`" /qn" -Verb RunAs -Wait }
            Else { Invoke-Gsudo { msiexec /i "$Using:Fetched" /qn } }
            Start-Sleep 4
        }
        Update-Path "$Env:ProgramFiles\gsudo\Current" "Process"
        Return $True
    }
    Catch { 
        Return $False
    }

}

Function Update-Lockscreen {

    Param(
        [String] $Payload
    )

    $KeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty "$KeyPath" "SubscribedContent-338387Enabled" -Value "0"
    $KeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    Invoke-Gsudo {
        New-Item "$Using:KeyPath" -Force -EA SI | Out-Null
        New-ItemProperty "$Using:KeyPath" "LockScreenImageStatus" -Value "1" -Force | Out-Null
        New-ItemProperty "$Using:KeyPath" "LockScreenImagePath" -Value "$Using:Payload" -Force | Out-Null
        New-ItemProperty "$Using:KeyPath" "LockScreenImageUrl" -Value "$Using:Payload" -Force | Out-Null
    }

}

Function Update-Nanazip {

    $Current = Expand-Version "*nanazip*"
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

Function Update-Plan {

    Param(
        [String] $Payload
    )

    $Program = "C:\Windows\System32\powercfg.exe"
    $Picking = (& "$Program" /l | ForEach-Object { If ($_.Contains("($Payload")) { $_.Split()[3] } })
    If ([String]::IsNullOrEmpty("$Picking") -And $Payload -Eq "Ultra") { Return }
    If ([String]::IsNullOrEmpty("$Picking")) { & "$Program" /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 }
    $Picking = (& "$Program" /l | ForEach-Object { If ($_.Contains("($Payload")) { $_.Split()[3] } })
    & "$Program" /s "$Picking"
    If ($Payload -Eq "Ultimate") {
        $Desktop = $Null -Eq (Get-WmiObject Win32_SystemEnclosure -ComputerName "localhost" | Where-Object ChassisTypes -In "{9}", "{10}", "{14}")
        $Desktop = $Desktop -Or $Null -Eq (Get-WmiObject Win32_Battery -ComputerName "localhost")
        If (-Not $Desktop) { & "$Program" /setacvalueindex $Picking sub_buttons lidaction 000 }
    }

}

Function Update-Powershell {

    $Starter = (Get-Item "$Env:ProgramFiles\PowerShell\*\pwsh.exe" -EA SI).FullName
    $Current = Expand-Version "$Starter"
    $Address = "https://api.github.com/repos/powershell/powershell/releases/latest"
    $Version = [Regex]::Match((Invoke-WebRequest "$Address" | ConvertFrom-Json).tag_name , "[\d.]+").Value
    $Updated = [Version] "$Current" -Ge [Version] "$Version"

    If (-Not $Updated) {
        Invoke-Gsudo {
            $ProgressPreference = "SilentlyContinue"
            Invoke-Expression "& { $(Invoke-RestMethod "https://aka.ms/install-powershell.ps1") } -UseMSI -Quiet" *> $Null
        }
    }

    If ([Version] $PSVersionTable.PSVersion.ToString() -Lt [Version] "7.0.0.0") { Invoke-Restart }

}

Function Update-Shortcut {

    Param(
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

Function Update-Path {

    Param (
        [String] $Payload,
        [ValidateSet("Machine", "Process", "User")] [String] $Section
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

Function Update-Timezone {

    Param(
        [String] $Payload
    )

    Set-TimeZone -Name "$Payload"
    Invoke-Gsudo {
        Start-Process "w32tm" "/unregister" -WindowStyle Hidden -Wait
        Start-Process "w32tm" "/register" -WindowStyle Hidden -Wait
        Start-Process "net" "start w32time" -WindowStyle Hidden -Wait
        Start-Process "w32tm" "/resync /force" -WindowStyle Hidden -Wait
    }

}

Function Update-Volume {

    Param(
        [String] $Payload
    )

    $Wscript = New-Object -ComObject WScript.Shell
    1..50 | ForEach-Object { $Wscript.SendKeys([Char]174) }
    If ($Payload -Ne 0) { 1..$($Payload / 2) | ForEach-Object { $Wscript.SendKeys([Char]175) } }

}
