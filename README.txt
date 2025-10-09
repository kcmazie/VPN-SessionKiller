# VPN-SessionKiller
A script to terminate Anyconnect VPN sessions on Cisco firewalls

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
