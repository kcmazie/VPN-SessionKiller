
<#==============================================================================
         File Name : VPN-SessionKiller.ps1
   Original Author : Kenneth C. Mazie (kcmjr AT kcmjr.com)
                   : 
       Description : This script is explicitly designed to detect and terminate Anyconnect
                   : VPN sessions on a Cisco firewall.  Using the Rensi PowerShell SSH 
                   : module the script remotes into a firewall and executes various 
                   : commands.  When run a GUI loads where the user can type in a user 
                   : name.  When text is detected in the input box an "Inspect" button 
                   : activates.  Pressing this button kicks off the SSH connection where 
                   : a query is run to determine if the selected user ID has an active 
                   : Anyconnect VPN session.  If found the session info is displayed in 
                   : the GUI window and a "Kill Connection" button lights up.  Clicking 
                   : this button reconnects to the firewall and issues a disconnect command
                   : to terminate the VPN session.  After a 5 second delay the inspection 
                   : routine is automatically run again to verify the session has been
                   : terminated.  An external XML options file is used to enter information
                   : such as firewall IP, SSH user and password.
                   : 
             Notes : Normal operation is with no command line options.  It is recommended 
                   : that pre-stored ENCRYPTED credentials are used.  The routine to encrypt
                   : the password in the external config file can be found here: 
                   : https://github.com/kcmazie/CredentialsWithKey.  If stored creds are 
                   : not used a pop-up prompt will ask for the firewall logon credentials 
                   : at each run.  Some debugging options exist and can be activated 
                   : changing the option from $False to $True within the script.  If the
                   : script is run from an editor that is detected and the extra console
                   : messages are automatically enabled.
                   :
      Requirements : The Rensi PowerShell SSH module is required.  If not detected the module 
                   : will be automatically installed during the first run.  A minimum PowerShell
                   : version of 5.1 is required.  PS version 7 will not work.
                   : 
   Option Switches : $Console - If Set to $true will display status during run (Defaults to 
                   :            $True)
                   : $Debug - If set to $true adds extra output on screen.  Forces console 
                   :          option to "true" (Defaults to $false)
                   :
          Warnings : When testing it's best to use an account that is not vital or in use.
                   : If you are using the VPN account being tested you will disconnect
                   : yourself.
                   :   
             Legal : Public Domain. Modify and redistribute freely. No rights reserved.
                   : SCRIPT PROVIDED "AS IS" WITHOUT WARRANTIES OR GUARANTEES OF 
                   : ANY KIND. USE AT YOUR OWN RISK. NO TECHNICAL SUPPORT PROVIDED.
                   : That being said, feel free to ask if you have questions...
                   :
           Credits : Code snippets and/or ideas came from many sources including but 
                   : not limited to the following:
                   : 
    Last Update by : Kenneth C. Mazie                                           
   Version History : v1.00 - 10-09-25 - Original 
    Change History : v1.10 - 00-00-00 - 
                   : #>
                   $ScriptVer = "1.00"    <#--[ Current version # used in script ]--
                   :                
==============================================================================#>
Clear-Host
#Requires -version 5

#--[ Variables ]---------------------------------------------------------------


#--[ RUNTIME OPTION VARIATIONS ]-----------------------------------------------
$Console = $false
$Debug = $false #True
#$SafeUpdate = $False
If($Debug){
    $Console = $true
}

#==============================================================================
#==[ Functions ]===============================================================

Function StatusMsg ($Msg, $Color, $ExtOption){
    If ($Null -eq $Color){
        $Color = "Magenta"
    }
    If ($ExtOption.Console){
        Write-Host "-- Script Status: " -NoNewline -ForegroundColor "Magenta"
        Write-host $Msg -ForegroundColor $Color
        }
    $Msg = ""
}

Function GetConsoleHost ($ExtOption){  #--[ Detect if we are using a script editor or the console ]--
    Switch ($Host.Name){
        'consolehost'{
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $False -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleMessage" -Value "PowerShell Console detected." -Force
        }
        'Windows PowerShell ISE Host'{
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $True -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleMessage" -Value "PowerShell ISE editor detected." -Force
        }
        'PrimalScriptHostImplementation'{
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $True -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "COnsoleMessage" -Value "PrimalScript or PowerShell Studio editor detected." -Force
        }
        "Visual Studio Code Host" {
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $True -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleMessage" -Value "Visual Studio Code editor detected." -Force
        }
    }
    If ($ExtOption.ConsoleState){
        StatusMsg "Detected session running from an editor..." "Magenta" $ExtOption
    }
    Return $ExtOption
}

Function PrepCredentials ($ExtOption){
    #--[ Prepare SSH Credentials ]--
   	If ($Null -eq $ExtOption.Password){
        $Base64String = ($ExtOption.FWKey)
	    $ByteArray = [System.Convert]::FromBase64String($Base64String)
	    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExtOption.FWUserName, ($ExtOption.FWPassword | ConvertTo-SecureString -Key $ByteArray)
	    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Credential" -Value $Credential
    }Else{
	    $Credential = $Host.ui.PromptForCredential("Enter your credentials","Please enter your UserID and Password.","","")
	    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Credential" -Value $Credential
    }
    Return $ExtOption
}

Function LoadConfig ($ExtOption,$ConfigFile){  #--[ Read and load configuration file ]-------------------------------------
    StatusMsg "Loading external config file..." "Magenta" $ExtOption
    if (Test-Path -Path $ConfigFile -PathType Leaf){                       #--[ Error out if configuration file doesn't exist ]--
        [xml]$Config = Get-Content $ConfigFile  #--[ Read & Load XML ]--    
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Domain" -Value $Config.Settings.General.Domain    
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "FWIPAddress" -Value $Config.Settings.General.FirewallIP
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "FWHostname" -Value $Config.Settings.General.FirewallHostname
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "FWUserName" -Value $Config.Settings.Credentials.UserName
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "FWPassword" -Value $Config.Settings.Credentials.Password
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "FWKey" -Value $Config.Settings.Credentials.Key
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailRecipient" -Value $Config.Settings.Email.EmailRecipient
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SmtpServer" -Value $Config.Settings.Email.SmtpServer
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailAltRecipient" -Value $Config.Settings.Email.EmailAltRecipient
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailSender" -Value $Config.Settings.Email.EmailSender
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailEnable" -Value $Config.Settings.Email.EmailEnable
		$ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SNMP3UserID" -Value $Config.Settings.SNMP.SNMP3UserID
		$ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SNMPAuthType" -Value $Config.Settings.SNMP.SNMPAuthType
		$ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SNMPPrivType" -Value $Config.Settings.SNMPSNMPPrivType
		$ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SNMPPassphrase" -Value $Config.Settings.SNMP.SNMPPassphrase
   		$ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SNMPPath" -Value $Config.Settings.SNMP.SNMPPath
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "VPNStatus" -Value $Null
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "UserName" -Value $Null
    }Else{
        StatusMsg "MISSING XML CONFIG FILE.  File is required.  Script aborted..." " Red" $True
        $Message = (
'--[ External XML config file example ]-----------------------------------
--[ To be named the same as the script and located in the same folder as the script ]--
--[ Email settings in example are for future use.                                   ]--

<?xml version="1.0" encoding="utf-8"?>
<Settings>
    <General>
        <Domain>company.org</Domain>
		<FirewallIP>10.10.10.10</FirewallIP>
		<FirewallHostname>firewall-01.company.org</FirewallHostname>
    </General>
    <Credentials>
		<UserName>administrator</UserName>
		<Password>76492MwAzAGUANABlADgAOQBmYANd11AEkAegAzAHGUAZABlADEAABrAEARgBPAFMAdAAwAFIAMQ16743f0423413bADIAOQAyADkANwA=</Password>
		<Key>zK2Z/ZMB7DiElDuG3BH1VG0ycIIjx7F3mb/a/+aUIp4=</Key>
	</Credentials>
	<SNMP>
		<SNMP3UserID>snmpuser</SNMP3UserID>
		<SNMPAuthType>MD5</SNMPAuthType>
		<SNMPPrivType>DES</SNMPPrivType>
		<SNMPPassphrase>snmppassphrase</SNMPPassphrase>		
	</SNMP>	
	<Email>
		<EmailEnable>$true</EmailEnable>
		<EmailSender>some_email@company.org</EmailSender>
        <SmtpServer>mailhost.company.org</SmtpServer>
        <SmtpPort>25</SmtpPort>
        <EmailRecipient>my_email@company.org</EmailRecipient>
    	<EmailAltRecipient>your_email@compnay.org</EmailAltRecipient>
    </Email>
</Settings>  ')
        Write-host $Message -ForegroundColor Yellow
    }
    Return $ExtOption
}

Function InstallModules{
    Try{
        if (!(Get-Module -Name PnP.PowerShell)) {       
            Get-Module -ListAvailable PnP.PowerShell | Import-Module | Out-Null    
            Install-Module -Name PnP.PowerShell -RequiredVersion 2.2.156
            Install-Module -Name PnP.PowerShell -RequiredVersion 1.12.0
        }
    }Catch{
        Write-Host "Error installing PNP module" -ForegroundColor "Red"
        Add-Content -path $ExtOption.Logfile -value $_.Error.Message
        Add-Content -path $ExtOption.Logfile -value $_.Exception.Message 
    }

    Try{
        if (!(Get-Module -Name SNMPv3)) {
            StatusMsg "Installing PowerShell SNMP module" "Magenta" $ExtOption
            Get-Module -ListAvailable SNMPv3 | Import-Module | Out-Null$Cmd
            Install-Module -Name SNMPv3
        }
    }Catch{
        Write-Host "Error installing SNMP module" -ForegroundColor "Red"
        Add-Content -path $ExtOption.Logfile -value $_.Error.Message
        Add-Content -path $ExtOption.Logfile -value $_.Exception.Message        
    }
}

Function SSHConnect ($ExtOption, $Command){  #--[ Perform the SSH Connection ]--
    $ErrorActionPreference = "Stop"
    Try{
        Get-SSHSession | Select-Object SessionId | Remove-SSHSession | Out-Null  #--[ Remove any existing sessions ]--
        New-SSHSession -ComputerName $ExtOption.FWIPAddress -AcceptKey -Credential $ExtOption.Credential | Out-Null
        $Session = Get-SSHSession -Index 0 
        $Stream = $Session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
        $Stream.Read() | Out-Null
        $Stream.Write("`n `n `n")
        $Stream.Write("$Command`n")
        Start-Sleep -millisec 100 
        $ResponseRaw = $Stream.Read()
        $Response = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}       
        While (($Response[$Response.Count -1]) -notlike "*>") {     
            Start-Sleep -millisec 50
            $ResponseRaw = $Stream.Read()   
            If ($ResponseRaw -like "*logged off*"){
                $Filtered = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}
            }    
            If ($ResponseRaw -like "*presently*"){
               $Filtered = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}
            }
            If ($ResponseRaw -like "*AnyConnect*"){
                $Filtered = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}
            }
            $Response = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}
        }        
        $Stream.Exit  
    }Catch{
        Write-Host "SSH Failure:" -ForegroundColor Red
        Write-host $_.Exception.Message
        Write-Host $_.Error.Message
    }
    Return $Filtered
}

Function GetSSH ($ExtOption, $Mode){
    StatusMsg ("Current SSH Mode = '$Mode'") "Cyan" $ExtOption
    Switch ($Mode){
        "Terminate"{  #--[ Kill the VPN session ]--
            StatusMsg "Terminating VPN Session..." "Red" $ExtOption
            $Command = "vpn-sessiondb logoff name "+$ExtOption.TargetUser+" noconfirm"
        }
        "Inspect"{  #--[ Check for a live VPN session for user ]--
            StatusMsg "Inspecting VPN Session..." "Cyan" $ExtOption
            $Command = "show vpn-sessiondb anyconnect filter name "+$ExtOption.TargetUser
        }
        "ReInspect"{  #--[ Check for a live VPN session for user ]--
            StatusMsg "Re-Inspecting VPN Session..." "Green" $ExtOption
            $Command = "show vpn-sessiondb anyconnect filter name "+$ExtOption.TargetUser
        }
        "Failover"{  #--[ Determine whether the node is primary or secondary ]--
            StatusMsg "Determining ASA Failover state..." "Yellow" $ExtOption
            $Command = 'show failover'
        }
    }
    StatusMsg ("Issuing SSH Command = '$Command'") "Cyan" $ExtOption

    $ScriptStatBox.BackColor = "lightgreen" 
    $ScriptStatBox.ForeColor = "blue"
    $ScriptStatBox.Text = "--- Connecting. Please Wait. ---"
    Start-Sleep -Seconds 2
    #--[ Call SSH ]--------
    $Filtered = SSHConnect $ExtOption $Command
    #----------------------
    $ScriptStatBox.BackColor = "lightgreen" 
    $ScriptStatBox.ForeColor = "blue"
    $ScriptStatBox.Text = "--- Parsing. Please Wait. ---"
    Start-Sleep -Seconds 2

    If ($Mode -eq "Terminate") {  #--[ Verify final character in response is a 1 ]--
        #--[ Expected Response: "INFO: Number of sessions with name "<TARGETNAME>" logged off : 1" ]--
        If (($Filtered[1].Split(":")[2].Trim()) -like "*1*"){
            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "VPNStatus" -Value "Terminated"
        }Else{
            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "VPNStatus" -Value "Failed"
        }    
    }Else{  #--[ Parse The Response ]----------------------
        If (($Filtered[1] -like "*presently*") -or ($Filtered[1] -like "*logged off*")){
            #--[ Expected response: "INFO: There are presently no active sessions of the type specified" ]--
            #--[ Alternate response: "INFO: Number of sessions with name "<TARGETNAME>" logged off : 1" ]--
            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "VPNStatus" -Value "VPN Not Found"
            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "UserName" -Value $ExtOption.TargetUser
            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "ReInspect" -Value $True
        }Elseif ($Filtered -like ("*"+$ExtOption.TargetUser+"*")){
            $Filtered = ($Filtered -replace '\s+', ' ').Trim()
            $SessionObj = $Filtered.split(" ")
            $Count=0
            ForEach ($line in $SessionObj){  
                If ($line -eq ":"){
                    If ($ExtOption.Debug){
                        write-host $SessionObj[($count-1)] -NoNewline -ForegroundColor Yellow
                        write-host " "$line" " -NoNewline
                        write-host $SessionObj[($count+1)] -ForegroundColor Cyan
                    }
                    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "VPNStatus" -Value "a VPN session is active." -ErrorAction:SilentlyContinue
                    Switch ($SessionObj[($count-1)]){
                        'Username'{
                            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "UserName" -Value $SessionObj[($count+1)]
                        }
                        'Index'{
                            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SessionIndex" -Value ($SessionObj[($count+1)]).trim()
                        }   
                        'Policy'{
                            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "GroupPolicy" -Value ($SessionObj[($count+1)])
                        }
                        'Group'{
                            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "TunnelGroup" -Value $SessionObj[($count+1)]
                        }
                        'Duration'{
                            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Duration" -Value $SessionObj[($count+1)]
                        }
                        'Inactivity'{
                            $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Inactivity" -Value $SessionObj[($count+1)]
                        }
                        'IP'{
                            If ($SessionObj[($count+1)] -like "10.*"){
                                $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "AssignedIP" -Value $SessionObj[($count+1)]
                            }Else{       
                                $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "PublicIP" -Value $SessionObj[($count+1)]
                            }
                        }
                    }
                }
                $Count++
            }
        }
    }
    If ($ExtOption.Debug){
        ShowVariables $ExtOption "Green"
    }
    Return $ExtOption     
}

Function ReloadForm ($Form){
    $Form.Close()
    $Form.Dispose()
    ActivateForm
}

Function KillForm ($Form) {
    $Form.Close()
    $Form.Dispose()
}
Function UpdateOutput ($Form){  #--[ Refreshes the infobox contents ]--
    $InfoBox.update()
    $InfoBox.Select($InfoBox.Text.Length, 0)
    $InfoBox.ScrollToCaret()
}

Function IsThereText ($TargetBox){  #--[ Checks for text in the text entry box(es) ]--
    if (($TargetBox.Text.Length -ge 3)){ 
        Return $true
    }else{
        Return $false
    }
}

Function InstallModules {
    if (!(Get-Module -Name posh-ssh*)) {    
        Try{  
            import-module -name posh-ssh
        }Catch{
            Write-host "-- Error loading Posh-SSH module." -ForegroundColor Red
            Write-host "Error: " $_.Error.Message  -ForegroundColor Red
            Write-host "Exception: " $_.Exception.Message  -ForegroundColor Red
        }
    }
}

Function ClearBoxes ($Form){
    $StatusBox.Text = ""
    #$UsernameBox.Text = ""
    $IndexBox.Text = ""
    $PolicyBox.Text = ""
    $GroupBox.Text = ""
    $DurationBox.Text = ""
    $InactivityBox.Text = ""
    $AssignedIPBox.Text = ""
    $PublicIPBox.Text = ""
}

Function PopulateBoxes ($ExtOption){
    $StatusBox.Text = $ExtOption.VPNStatus
    $UsernameBox.Text = $ExtOption.TargetUser
    $IndexBox.Text = $ExtOption.SessionIndex
    $PolicyBox.Text = $ExtOption.GroupPolicy
    $GroupBox.Text = $ExtOption.TunnelGroup
    $DurationBox.Text = $ExtOption.Duration
    $InactivityBox.Text = $ExtOption.Inactivity
    $AssignedIPBox.Text = $ExtOption.AssignedIP
    $PublicIPBox.Text = $ExtOption.PublicIP
}

Function ShowVariables ($ExtOption,$Color){
    If ($Null -eq $Color){$Color = "Cyan"}
    Foreach ($Property in $ExtOption.psobject.Properties) {
        Write-Host $($property.Name).PadRight(18," ") -ForegroundColor Yellow -NoNewline
        Write-host "= " -NoNewline
        Write-host $($property.Value) -ForegroundColor $Color
    }
}
#==[ End of Functions ]===================================================

#==[ Begin ]============================================================== 
InstallModules  #--[ Load required PowerShell modules ]--
$ScriptName = ($MyInvocation.MyCommand.Name).Replace(".ps1","" ) 
$ConfigFile = $PSScriptRoot+"\"+$ScriptName+".xml"

#--[ Load external XML options file into custom runtime object ]--
$ExtOption = New-Object -TypeName psobject   #--[ Object to hold runtime options ]--
$ExtOption = LoadConfig $ExtOption $ConfigFile
$ExtOption = GetConsoleHost $ExtOption       #--[ Detect Runspace ]--
$ExtOption = PrepCredentials $ExtOption      #--[ Get Credentials ]--

#--[ Additional runtime variations into options object ]--
If ($Console){
    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Console" -Value $True
} 
If ($Debug){
    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Debug" -Value $True
    StatusMsg "--[ Debug mode: Option File Contents ]---------------------" "Yellow" $ExtOption
    $ExtOption
}
StatusMsg "--[ Beginning Run ]------------------------------------" "Green" $ExtOption

#--[ Prep GUI ]------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$Icon = [System.Drawing.SystemIcons]::Information

#--[ Define Form ]---------------------------------------------------------------
[int]$FormWidth = 350
[int]$FormHeight = 609 
[int]$FormHCenter = ($FormWidth / 2)   # 175 Horizontal center point
[int]$FormVCenter = ($FormHeight / 2)  # 279 Vertical center point
[int]$ButtonHeight = 25
[int]$TextHeight = 20

#--[ Create Form ]---------------------------------------------------------------------
$Form = New-Object System.Windows.Forms.Form    
#$Script:Form.size = New-Object System.Drawing.Size($Script:FormWidth,$Script:FormHeight)
#--[ The following locks the form size or can be used to allow the form to grow downwards ]--
#--[ to allow dynamic growth depending on number of options ]--
$Form.minimumSize = New-Object System.Drawing.Size($Script:FormWidth,$Script:FormHeight)
$Form.maximumSize = New-Object System.Drawing.Size($Script:FormWidth,($Script:FormHeight))
$Notify = New-Object system.windows.forms.notifyicon
$Notify.icon = $Icon        #--[ NOTE: Available tooltip icons are = warning, info, error, and none
$Notify.visible = $true
[int]$FormVTop = 0 
[int]$ButtonLeft = 55
[int]$ButtonTop = ($FormHeight - 75)
$Form.Text = "$ScriptName v$ScriptVer"
$Form.StartPosition = "CenterScreen"
$Form.KeyPreview = $true
$Form.Add_KeyDown({if ($_.KeyCode -eq "Escape"){$Form.Close();$Stop = $true}})
$ButtonFont = New-Object System.Drawing.Font("New Times Roman",9,[System.Drawing.FontStyle]::Bold)

#--[ Form Title Label ]-----------------------------------------------------------------
$BoxLength = 350
$LineLoc = 5
$FormLabelBox = New-Object System.Windows.Forms.Label
$FormLabelBox.Font = New-Object System.Drawing.Font("Tahoma",10,[System.Drawing.FontStyle]::Bold) 
$FormLabelBox.Location = New-Object System.Drawing.Size(($FormHCenter-($BoxLength/2)-10),$LineLoc)
$FormLabelBox.size = New-Object System.Drawing.Size($BoxLength,$ButtonHeight)
$FormLabelBox.TextAlign = 2 
$FormLabelBox.ForeColor = "Blue"
$FormLabelBox.Text = "Anyconnect VPN Session Killer." #$ScriptName
$Form.Controls.Add($FormLabelBox)

#--[ User Credential Label ]-------------------------------------------------------------
$BoxLength = 290
$LineLoc = 32
$UserCredLabel = New-Object System.Windows.Forms.Label 
$UserCredLabel.Location = New-Object System.Drawing.Point(($FormHCenter-($BoxLength/2)-10),$LineLoc)
$UserCredLabel.Size = New-Object System.Drawing.Size($BoxLength,$TextHeight) 
$UserCredLabel.ForeColor = "Black" 
$UserCredLabel.Text = "Enter the User ID of the target user (without domain):"
$UserCredLabel.TextAlign = 2 
$Form.Controls.Add($UserCredLabel) 

#--[ User ID Text Input Box ]-------------------------------------------------------------
$BoxLength = 140
$LineLoc = 55
$UserIDTextBox = New-Object System.Windows.Forms.TextBox 
$UserIDTextBox.Location = New-Object System.Drawing.Point(($FormHCenter-($BoxLength/2)-10),$LineLoc)
$UserIDTextBox.Size = New-Object System.Drawing.Size($BoxLength,$TextHeight) 
$UserIDTextBox.TabIndex = 2
$UserIDTextBox.Text = "Enter User 611 here:"
$UserIDTextBox.ForeColor = "DarkGray"
$UserIDTextBox.Enabled = $True
$UserIDTextBox.TextAlign = 2
$UserIDTextBox.Add_GotFocus({
    $UserIDTextBox.Text = ""
})

$UserIDTextBox.add_TextChanged({
    If ($UserIDTextBox.Text.Length -ge 1){ 
        $InspectButton.Enabled = $True
        $InspectButton.Font = New-Object System.Drawing.Font("New Times Roman",9,[System.Drawing.FontStyle]::Bold)
        $UserIDTextBox.ForeColor = "Blue"
        $InspectButton.ForeColor = "Green"
    }Else{
        $InspectButton.Enabled = $False
        $InspectButton.Font = New-Object System.Drawing.Font("New Times Roman",9,[System.Drawing.FontStyle]::Regular)
        $ProcessButton.Enabled = $False
    } 
    $ErrorActionPreference = "Stop"
})
$Form.Controls.Add($UserIDTextBox) 
  
#--[ Global Form Result Box Offsets ]-----------------------------------------------------------
$LineAdd = 25
$BoxLength1 = 110
$BoxLength2 = 170
$LabelOffset = 5
$BoxOffset = 125

#================================================================================================
#--[ Firewall Hostname Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = 20 
$HostnameLabel = New-Object System.Windows.Forms.Label 
$HostnameLabel.Location = New-Object System.Drawing.Size($LabelOffset,($LineLoc+2))
$HostnameLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$HostnameLabel.Text = "Firewall Hostname:"
$HostnameLabel.Enabled = $True
$HostnameLabel.TextAlign = 2
$Form.Controls.Add($HostnameLabel) 

#--[ Firewall Hostname Box ]---------------------------------------------------------------------
$BoxLength = 244  
$HostnameBox = New-Object System.Windows.Forms.TextBox
$HostnameBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$HostnameBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$HostnameBox.BackColor = $Form.BackColor
$HostnameBox.ForeColor = "blue"
$HostnameBox.Text = $ExtOption.FWHostname
$HostnameBox.Enabled = $True
$HostnameBox.ReadOnly = $True
$HostnameBox.TextAlign = 2
$Form.Controls.Add($HostnameBox)

#--[ Firewall IPAddress Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$IPAddressLabel = New-Object System.Windows.Forms.Label 
$IPAddressLabel.Location = New-Object System.Drawing.Size($LabelOffset,($LineLoc+2))
$IPAddressLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$IPAddressLabel.Text = "Firewall IP:"
$IPAddressLabel.Enabled = $True
$IPAddressLabel.TextAlign = 2
$Form.Controls.Add($IPAddressLabel) 

#--[ Firewall IPAddress Box ]-------------------------------------------------------------------
$BoxLength = 244  
$IPAddressBox = New-Object System.Windows.Forms.TextBox
$IPAddressBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$IPAddressBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$IPAddressBox.BackColor = $Form.BackColor
$IPAddressBox.ForeColor = "blue"
$IPAddressBox.Text = $ExtOption.FWIPAddress
$IPAddressBox.Enabled = $True
$IPAddressBox.ReadOnly = $True
$IPAddressBox.TextAlign = 2
$Form.Controls.Add($IPAddressBox)

#--[ Firewall User Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$FWUserLabel = New-Object System.Windows.Forms.Label 
$FWUserLabel.Location = New-Object System.Drawing.Size($LabelOffset,($LineLoc+2)) 
$FWUserLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$FWUserLabel.Text = "Firewall User:"
$FWUserLabel.Enabled = $True
$FWUserLabel.TextAlign = 2
$Form.Controls.Add($FWUserLabel) 

#--[ Firewall User Box ]-------------------------------------------------------------------
$BoxLength = 244  
$FWUserBox = New-Object System.Windows.Forms.TextBox
$FWUserBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$FWUserBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$FWUserBox.BackColor = $Form.BackColor
$FWUserBox.ForeColor = "blue"
$FWUserBox.Text = $ExtOption.FWUserName
$FWUserBox.Enabled = $True
$FWUserBox.ReadOnly = $True
$FWUserBox.TextAlign = 2
$Form.Controls.Add($FWUserBox)

#--[ Firewall Info Group Box ]-------------------------------------------------------------
$Range = @($HostnameLabel,$HostnameBox,$IPAddressLabel,$IPAddressBox,$FWUserLabel,$FWUserBox) 
$LineLoc = 114 
$TargetGroupBox = New-Object System.Windows.Forms.GroupBox
$TargetGroupBox.Location = New-Object System.Drawing.Point((($FormHCenter/2)-72),$LineLoc) 
$TargetGroupBox.size = '300,100'
$TargetGroupBox.AutoSize = $False
$TargetGroupBox.text = "Firewall Details:"    
$TargetGroupBox.Controls.AddRange($Range)
$Form.controls.add($TargetGroupBox)

#=============================================================================================
#--[ Script Status Label ]--------------------------------------------------------------------
$BoxLength = 100
$LineLoc = 20 
$ScriptStatLabel = New-Object System.Windows.Forms.Label #TextBox
$ScriptStatLabel.Location = New-Object System.Drawing.Size($LabelOffset,($LineLoc+2))
$ScriptStatLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$ScriptStatLabel.Text = "Script Status:"
$ScriptStatLabel.Enabled = $True
$ScriptStatLabel.TextAlign = 2
$Form.Controls.Add($ScriptStatLabel) 

#--[ Script Status Box ]-------------------------------------------------------------------
$BoxLength = 100   
$ScriptStatBox = New-Object System.Windows.Forms.TextBox
$ScriptStatBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$ScriptStatBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$ScriptStatBox.BackColor = "lightblue"
$ScriptStatBox.ForeColor = "blue"
$ScriptStatBox.Enabled = $True
$ScriptStatBox.text = "--- Idle ---"   
$ScriptStatBox.ReadOnly = $True
$ScriptStatBox.TextAlign = 2
$Form.Controls.Add($ScriptStatBox)

#--[ Script Status Group Box ]---------------------------------------------------------------
$Range = @($ScriptStatLabel,$ScriptStatBox) 
$LineLoc = 217 
$ScriptStatGroupBox = New-Object System.Windows.Forms.GroupBox
$ScriptStatGroupBox.Location = New-Object System.Drawing.Point((($FormHCenter/2)-72),$LineLoc) 
$ScriptStatGroupBox.size = '300,49'
$ScriptStatGroupBox.AutoSize = $False
$ScriptStatGroupBox.text = "Status Messages:"    
$ScriptStatGroupBox.Controls.AddRange($Range)
$Form.controls.add($ScriptStatGroupBox)

#=============================================================================================
#--[ Session Status Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = 20 
$StatusLabel = New-Object System.Windows.Forms.Label #TextBox
$StatusLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc)
$StatusLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$StatusLabel.Text = "Session Status:"
$StatusLabel.Enabled = $True
$StatusLabel.TextAlign = 2
$Form.Controls.Add($StatusLabel) 

#--[ Session Status Box ]-------------------------------------------------------------------
$BoxLength = 244  
$StatusBox = New-Object System.Windows.Forms.TextBox
$StatusBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$StatusBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$StatusBox.BackColor = $Form.BackColor
$StatusBox.ForeColor = "blue"
$StatusBox.Enabled = $True
$StatusBox.ReadOnly = $True
$StatusBox.TextAlign = 2
$Form.Controls.Add($StatusBox)

#--[ Session Username Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$UsernameLabel = New-Object System.Windows.Forms.Label 
$UsernameLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc) 
$UsernameLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$UsernameLabel.Text = "VPN User:"
$UsernameLabel.Enabled = $True
$UsernameLabel.TextAlign = 2
$Form.Controls.Add($UsernameLabel) 

#--[ Session Username Box ]-------------------------------------------------------------------
$BoxLength = 244  
$UsernameBox = New-Object System.Windows.Forms.TextBox
$UsernameBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$UsernameBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$UsernameBox.BackColor = $Form.BackColor
$UsernameBox.ForeColor = "blue"
$UsernameBox.Enabled = $True
$UsernameBox.ReadOnly = $True
$UsernameBox.TextAlign = 2
$Form.Controls.Add($UsernameBox)

#--[ Session Index Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$IndexLabel = New-Object System.Windows.Forms.Label 
$IndexLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc) 
$IndexLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$IndexLabel.Text = "Session Index:"
$IndexLabel.Enabled = $True
$IndexLabel.TextAlign = 2
$Form.Controls.Add($IndexLabel) 

#--[ Session Index Box ]-------------------------------------------------------------------
$BoxLength = 244  
$IndexBox = New-Object System.Windows.Forms.TextBox
$IndexBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$IndexBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$IndexBox.BackColor = $Form.BackColor
$IndexBox.ForeColor = "blue"
$IndexBox.Enabled = $True
$IndexBox.ReadOnly = $True
$IndexBox.TextAlign = 2
$Form.Controls.Add($IndexBox)

#--[ Session Policy Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$PolicyLabel = New-Object System.Windows.Forms.Label 
$PolicyLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc) 
$PolicyLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$PolicyLabel.Text = "Session Policy:"
$PolicyLabel.Enabled = $True
$PolicyLabel.TextAlign = 2
$Form.Controls.Add($PolicyLabel) 

#--[ Session Policy Box ]-------------------------------------------------------------------
$BoxLength = 244  
$PolicyBox = New-Object System.Windows.Forms.TextBox
$PolicyBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$PolicyBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$PolicyBox.BackColor = $Form.BackColor
$PolicyBox.ForeColor = "blue"
$PolicyBox.Enabled = $True
$PolicyBox.ReadOnly = $True
$PolicyBox.TextAlign = 2
$Form.Controls.Add($PolicyBox)

#--[ Session Group Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$GroupLabel = New-Object System.Windows.Forms.Label 
$GroupLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc) 
$GroupLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$GroupLabel.Text = "Session Group:"
$GroupLabel.Enabled = $True
$GroupLabel.TextAlign = 2
$Form.Controls.Add($GroupLabel) 

#--[ Session Group Box ]-------------------------------------------------------------------
$BoxLength = 200  
$GroupBox = New-Object System.Windows.Forms.TextBox
$GroupBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc)
$GroupBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$GroupBox.BackColor = $Form.BackColor
$GroupBox.ForeColor = "blue"
$GroupBox.Enabled = $True
$GroupBox.ReadOnly = $True
$GroupBox.TextAlign = 2
$Form.Controls.Add($GroupBox)

#--[ Session Duration Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$DurationLabel = New-Object System.Windows.Forms.Label 
$DurationLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc) 
$DurationLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$DurationLabel.Text = "Session Duration:"
$DurationLabel.Enabled = $True
$DurationLabel.TextAlign = 2
$Form.Controls.Add($DurationLabel) 

#--[ Session Duration Box ]-------------------------------------------------------------------
$BoxLength = 244  
$DurationBox = New-Object System.Windows.Forms.TextBox
$DurationBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$DurationBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$DurationBox.BackColor = $Form.BackColor
$DurationBox.ForeColor = "blue"
$DurationBox.Enabled = $True
$DurationBox.ReadOnly = $True
$DurationBox.TextAlign = 2
$Form.Controls.Add($DurationBox)

#--[ Session Inactivity Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$InactivityLabel = New-Object System.Windows.Forms.Label 
$InactivityLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc) 
$InactivityLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$InactivityLabel.Text = "Session Inactivity:"
$InactivityLabel.Enabled = $True
$InactivityLabel.TextAlign = 2
$Form.Controls.Add($InactivityLabel) 

#--[ Session Inactivity Box ]-------------------------------------------------------------------
$BoxLength = 244  
$InactivityBox = New-Object System.Windows.Forms.TextBox
$InactivityBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$InactivityBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$InactivityBox.BackColor = $Form.BackColor
$InactivityBox.ForeColor = "blue"
$InactivityBox.Enabled = $True
$InactivityBox.ReadOnly = $True
$InactivityBox.TextAlign = 2
$Form.Controls.Add($InactivityBox)

#--[ Session AssignedIP Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$AssignedIPLabel = New-Object System.Windows.Forms.Label 
$AssignedIPLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc)
$AssignedIPLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$AssignedIPLabel.Text = "Session AssignedIP:"
$AssignedIPLabel.Enabled = $True
$AssignedIPLabel.TextAlign = 2
$Form.Controls.Add($AssignedIPLabel) 

#--[ Session AssignedIP Box ]-------------------------------------------------------------------
$BoxLength = 244  
$AssignedIPBox = New-Object System.Windows.Forms.TextBox
$AssignedIPBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$AssignedIPBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$AssignedIPBox.BackColor = $Form.BackColor
$AssignedIPBox.ForeColor = "blue"
$AssignedIPBox.Enabled = $True
$AssignedIPBox.ReadOnly = $True
$AssignedIPBox.TextAlign = 2
$Form.Controls.Add($AssignedIPBox)

#--[ Session PublicIP Label ]-------------------------------------------------------------------
$BoxLength = 100
$LineLoc = $LineLoc+$LineAdd
$PublicIPLabel = New-Object System.Windows.Forms.Label 
$PublicIPLabel.Location = New-Object System.Drawing.Size($LabelOffset,$LineLoc)
$PublicIPLabel.Size = New-Object System.Drawing.Size($BoxLength1,$TextHeight) 
$PublicIPLabel.Text = "Session PublicIP:"
$PublicIPLabel.Enabled = $True
$PublicIPLabel.TextAlign = 2
$Form.Controls.Add($PublicIPLabel) 

#--[ Session PublicIP Box ]-------------------------------------------------------------------
$BoxLength = 244  
$PublicIPBox = New-Object System.Windows.Forms.TextBox
$PublicIPBox.Location = New-Object System.Drawing.Size($BoxOffset,$LineLoc) 
$PublicIPBox.Size = New-Object System.Drawing.Size(($BoxLength2-9),$TextHeight) 
$PublicIPBox.BackColor = $Form.BackColor
$PublicIPBox.ForeColor = "blue"
$PublicIPBox.Enabled = $True
$PublicIPBox.ReadOnly = $True
$PublicIPBox.TextAlign = 2
$Form.Controls.Add($PublicIPBox)

#--[ Session Info Group Box ]-------------------------------------------------------------------
$Range = @($StatusLabel,$StatusBox,$UsernameLabel,$UsernameBox,$IndexLabel,$IndexBox,$PolicyLabel,$PolicyBox,$GroupLabel,$GroupBox,$DurationLabel,$DurationBox,$InactivityLabel,$InactivityBox,$AssignedIPLabel,$AssignedIPBox,$PublicIPLabel,$PublicIPBox) 
$LineLoc = 268 
$StatusGroupBox = New-Object System.Windows.Forms.GroupBox
$StatusGroupBox.Location = New-Object System.Drawing.Point((($FormHCenter/2)-72),$LineLoc) 
$StatusGroupBox.size = '300,253'
$StatusGroupBox.AutoSize = $False
$StatusGroupBox.text = "Results:"    
$StatusGroupBox.Controls.AddRange($Range)
$Form.controls.add($StatusGroupBox)

#--[ Inspect Button ]-------------------------------------------------------------------------
$BoxLength = 120
$LineLoc = 82 
$InspectButton = New-Object System.Windows.Forms.Button
$InspectButton.Location = New-Object System.Drawing.Point(($FormHCenter-($BoxLength/2)-10),$LineLoc)
$InspectButton.Size = New-Object System.Drawing.Size($BoxLength,$ButtonHeight)
$InspectButton.TabIndex = 4
$InspectButton.Text = "Click to Inspect"
$InspectButton.Font = New-Object System.Drawing.Font("New Times Roman",9,[System.Drawing.FontStyle]::Regular)
$InspectButton.Enabled = $False
$InspectButton.Add_Click({
    $UserID = $UserIDTextBox.Text
    If ($UserID -like "ah\*"){      #--[ Strip off leading domain if it was included ]--
        $UserIDTextBox.Text = ""
        Start-Sleep -Milliseconds 500
        $UserIDTextBox.Text = $UserID.Split("\")[1]
    }
    If ($UserID -like "*@ah*"){     #--[ Strip off trailing domain if it was included ]--
        $UserIDTextBox.Text = ""
        Start-Sleep -sec 1
        $UserIDTextBox.Text = $UserID.Split("@")[0]
    }
    ClearBoxes $Form
    $StatusBox.BackColor = $Form.BackColor
    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "TargetUser" -Value $UserIDTextBox.Text

<#--[ Use to get the active ASA in a failover pair ]--
    $StatusBox.Text = "--- Inspecting ASA ---"
    $StatusBox.BackColor = "salmon"    
    #==[ Get firewall failover status ]==========
    $ExtOption = GetSSH $ExtOption "Failover"
    #============================================    
    If ($ExtOption.HASecondary){
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "HAPrimary" -Value $UserIDTextBox.Text
    }Else{
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "HAPrimary" -Value $UserIDTextBox.Text
    }
    Start-Sleep -Seconds 10
#>
    $ScriptStatBox.ForeColor = "blue" 
    $ScriptStatBox.BackColor = "lightgreen"   
    $ScriptStatBox.Text = "--- Inspecting. Please Wait. ---"
    Start-Sleep -Seconds 2    
    $StatusBox.Text = ""
    $ProcessButton.Enabled = $False
    $ProcessButton.Text = "Execute"
    $ProcessButton.Font = $ButtonFont

    #==[ Inspect sessions on firewall ]==========
    StatusMsg "Calling SSH" "Cyan" $ExtOption 
    $ExtOption = GetSSH $ExtOption "Inspect"
    #============================================

    If ($ExtOption.Debug){
        ShowVariables $ExtOption "cyan"
    }

    $ScriptStatBox.BackColor = "lightblue" 
    $ScriptStatBox.Text = "--- Idle ---"
    If ($ExtOption.VPNStatus -like "*not found*"){
        StatusMsg "VPN Session was not found..." "Green" $ExtOption
        ClearBoxes $Form
        $StatusBox.BackColor = "lightgreen" 
        $StatusBox.Text = $ExtOption.VPNStatus
        $UsernameBox.Text = $ExtOption.TargetUser
        $ProcessButton.Enabled = $False
        $ProcessButton.Font = $ButtonFont
    }Else{
        StatusMsg "Identified a live VPN Session.  Click on KILL button to terminate." "Yellow" $ExtOption
        $StatusBox.BackColor = "lightpink"
        PopulateBoxes $ExtOption
        $ProcessButton.Enabled = $True
        $ProcessButton.Text = "Kill Connection"
        $ProcessButton.ForeColor = "Green" 
    }
})
$Form.Controls.Add($InspectButton)

#--[ KILL-IT Button ]------------------------------------------------------------------------
$LineLoc = $FormHeight-76
$ProcessButton = New-Object System.Windows.Forms.Button
$ProcessButton.Location = New-Object System.Drawing.Size(($FormHCenter-($BoxLength/2)+70),$LineLoc)
$ProcessButton.Size = New-Object System.Drawing.Size($BoxLength,$ButtonHeight)
$ProcessButton.Text = "Execute"
$ProcessButton.Enabled = $False
$ProcessButton.Font = $ButtonFont
$ProcessButton.TabIndex = 5
$ProcessButton.Add_Click({
    #==[ Terminate the session on firewall ]==========
    $ScriptStatBox.Text = "--- Terminating VPN Session ---"
    Start-Sleep -Seconds 2
    $ScriptStatBox.ForeColor = "yellow" 
    $ScriptStatBox.BackColor = "darkred" 
    $StatusBox.BackColor = $Form.BackColor
    ClearBoxes $Form
    #================================================= 
    StatusMsg "Calling SSH" "Cyan" $ExtOption
    $ExtOption = GetSSH $ExtOption "Terminate"
    #=================================================
    
    If ($ExtOption.Debug){
        ShowVariables $ExtOption "red"
    }

    If ($ExtOption.VPNStatus -like "*Terminated*"){
        StatusMsg "VPN Session was terminated.  Rechecking in 5 sec." "Green" $ExtOption
        $StatusBox.BackColor = "lightgreen"
        $StatusBox.Text = $ExtOption.VPNStatus
        $ScriptStatBox.BackColor = "lightgreen" 
        $ScriptStatBox.ForeColor = "blue" 
        $ScriptStatBox.Text = "--- Pausing for 5 Seconds ---"
        Start-Sleep -sec 5
        $ScriptStatBox.Text = "--- Re-Inspecting ---"
        Start-Sleep -seconds 2    

        #==[ Inspect sessions on firewall ]==========
        StatusMsg "Calling SSH" "Cyan" $ExtOption
        $ExtOption = GetSSH $ExtOption "ReInspect"
        #============================================

        If ($ExtOption.Debug){
            ShowVariables $ExtOption "red"
        }   

        $ScriptStatBox.BackColor = "lightblue" 
        $ScriptStatBox.Text = "--- Idle ---"
       If ($ExtOption.ReInspect){            
            StatusMsg "VPN Session verified terminated..." "Green" $ExtOption
            ClearBoxes $Form
            $StatusBox.BackColor = "lightgreen" 
            $StatusBox.Text = $ExtOption.VPNStatus
            $UsernameBox.Text = $ExtOption.TargetUser
            $ProcessButton.Enabled = $False
            $ProcessButton.Font = $ButtonFont
        }Else{
            StatusMsg "VPN Session was NOT terminated... Please Retry." "Red" $ExtOption
            $StatusBox.BackColor = "lightpink"
            $StatusBox.Text = $ExtOption.VPNStatus
            $UsernameBox.Text = $ExtOption.TargetUser
            $IndexBox.Text = $ExtOption.SessionIndex
            $PolicyBox.Text = $ExtOption.GroupPolicy
            $GroupBox.Text = $ExtOption.TunnelGroup
            $DurationBox.Text = $ExtOption.Duration
            $InactivityBox.Text = $ExtOption.Inactivity
            $AssignedIPBox.Text = $ExtOption.AssignedIP
            $PublicIPBox.Text = $ExtOption.PublicIP
            $ProcessButton.Enabled = $True
            $ProcessButton.Text = "Kill Connection"
            $ProcessButton.ForeColor = "Green" 
        }  
    }Else{
        StatusMsg "VPN Session was NOT terminated... Please Retry." "Red" $ExtOption
        $StatusBox.BackColor = "lightpink"
        $StatusBox.Text = "Termination Failed"
    }
})
$Form.Controls.Add($ProcessButton)

#--[ CLOSE Button ]------------------------------------------------------------------------
$CloseButton = New-Object System.Windows.Forms.Button
$CloseButton.Location = New-Object System.Drawing.Size(($FormHCenter-($BoxLength/2)-70),$LineLoc)
$CloseButton.Size = New-Object System.Drawing.Size($BoxLength,$ButtonHeight)
$CloseButton.TabIndex = 2
$CloseButton.Text = "Cancel/Close"
$CloseButton.Add_Click({
    $Form.close()
    $Stop = $true
})
$Form.Controls.Add($CloseButton)

#--[ Open The Form ]--
$Form.topmost = $true
$Form.Add_Shown({$Form.Activate()})
[void] $Form.ShowDialog()
if($Stop -eq $true){$Form.Close();break;break}

Write-Host ""

StatusMsg "--- COMPLETED ---" "red" $ExtOption
