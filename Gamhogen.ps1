Function RunUpdateAppearance {

    Return $True

}

Function RunUpdateWindows {

    Return $True

}

Function RunUpdateAmd {

    Return 1 / 0

}
Function RunUpdateFirefox {

    Return $True

}
Function RunUpdateHeroic {

    Return $True

}
Function RunUpdateHydra {

    Return $True

}
Function RunUpdateLudusavi {

    Return $True

}
Function RunUpdateNvidia {

    Return $True

}
Function RunUpdateSteam {

    Return $True

}

If ($MyInvocation.InvocationName -Ne "." -Or "$Env:TERM_PROGRAM" -Eq "Vscode") {
    
    # $Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/Gamhogen.ps1" ; `
    # $Fetched = New-Item $Env:Temp\Gamhogen.ps1 -F ; Invoke-WebRequest $Address -O $Fetched ; `
    # Try { Pwsh -Ep Bypass $Fetched } Catch { Powershell -Ep Bypass $Fetched }

    # $Timeout = (Get-Date).AddSeconds(60)
    # While ((Get-Date) -Lt $Timeout) {
    #     If (Get-NetAdapter | Where-Object { $_.Status -Eq "Up" }) { Return }
    #     Start-Sleep -Seconds 2
    # }

    $Address = "https://raw.githubusercontent.com/olankens/whelpers/HEAD/Whelpers.psm1"
    $Content = ([Scriptblock]::Create((New-Object System.Net.WebClient).DownloadString($Address)))
    New-Module -Name "$Address" -ScriptBlock $Content -EA SI > $Null

    $Heading = "
    +--------------------------------------------------------------------+
    |                                                                    |
    |  > GAMHOGEN                                                        |
    |                                                                    |
    |  > WINDOWS AUTOMATIC SETUP FOR GAMERS                              |
    |                                                                    |
    +--------------------------------------------------------------------+
    "

    $Members = @(
        { RunUpdateWindows },
        { RunUpdateAmd },
        { RunUpdateNvidia },
        { RunUpdateFirefox },
        { RunUpdateHeroic },
        { RunUpdateHydra },
        { RunUpdateLudusavi },
        { RunUpdateSteam },
        { RunUpdateAppearance }
    )

    RunUpdateAll -Heading $Heading -Members $Members

}