﻿<#
Script Name: OTC Network Configuration Utility
Author: Christopher Bates
Date: 2024-03-07
Description: This script provides a menu-driven interface for configuring network settings and automating tasks on an OTC workstation.
Version: 1.58
Contact: cb0988836@otc.edu
#>


######################### Initialization #########################

#Reload with Elevate privileges if not Administrator#
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) 
{
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) 
    {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

########################### Functions ###########################


###Echo Request Setup function###
function EchoSetup()
{
    #Ask user whether to disable or enable echo requests#
    Write-Host ""
    Write-Host "   1) Enable Echo Requests" -ForegroundColor Gray
    Write-Host "   2) Disable Echo Requests" -ForegroundColor Gray
    $selection2 = Read-Host -Prompt "   > Select an option"

    #Translate selection for Enabled setting#
    if ($selection2 -eq '1')
    {
        $enable = 'true'
    } 
    else
    {
        $enable = 'false'
    }

    #If selection is valid apply settings#
    if ($selection2 -in 1..2)
    {
        #Set ICMP setting#
        Set-NetFirewallRule -Enabled $enable -Name $ruleName -ErrorAction SilentlyContinue

        #Display new settings#
        Write-Host ""
        Write-Host ("Inbound Echo Requests set to " + $enable.ToUpper()) -ForegroundColor Yellow
        Get-NetFirewallRule -Name $ruleName
    }
    else
    {
        Write-Host "     Invalid selection." -ForegroundColor Yellow
        Write-Host ""
    }
    Read-Host -Prompt "Press RETURN to go back to Menu"
}


###Ip Setup function###
function IpSetup()
{
    Write-Host ""
    Write-Host " **********************************" -ForegroundColor DarkGray
    Write-Host " Ip Configuration Wizard" -ForegroundColor Cyan
    Write-Host ""

    #Ask user for info#
    $class = Read-Host -Prompt " > What is your classroom number?"
    $computer = Read-Host -Prompt " > What is your computer number?"

    #Format IP address with class and computer number#
    $ip = "192.168." + $class + "." + $computer

    #Format default gateway with class number#
    $gateway = "192.168." + $class + ".254"

    #Get network adapters#
    Get-NetAdapter | Select-Object ifIndex, Name, InterfaceDescription | Sort-Object -Property ifIndex | Format-Table

    #Ask user for adapter choice#
    $choice = Read-Host -Prompt " > Please select your Interface Index"
    $adapter = Get-NetAdapter -InterfaceIndex $choice

    #Display new settings#
    Write-Host ""
    Write-Host ""$adapter.Name "IPv4 Settings"
    Write-Host " **********************************" -ForegroundColor DarkGray
    Write-Host " Interface:" $adapter.InterfaceDescription -ForegroundColor Yellow
    Write-Host " IP Address:" $ip -ForegroundColor Yellow
    Write-Host " Subnet Mask: 255.255.255.0" -ForegroundColor Yellow
    Write-Host " Default Gateway:" $gateway -ForegroundColor Yellow
    Write-Host " DNS1: 172.30.0.42" -ForegroundColor Yellow
    Write-Host " DNS2: 172.30.0.43" -ForegroundColor Yellow
    Write-Host " **********************************" -ForegroundColor DarkGray

    #Ask user for confirmation#
    $confirmation = Read-Host -Prompt " > Do you want to apply these settings? [Y/n]"

    #If input is invalid, skip network setup process#
    if ($class -notin 0..255 -and $computer -notin 1..255)
    {
        Write-Host " Invalid everything..." -ForegroundColor Yellow
        Write-Host ""
    }
    elseif ($computer -notin 1..255)
    {
        Write-Host " Invalid computer number..." -ForegroundColor Yellow
        Write-Host ""
    }
    elseif ($class -notin 0..255)
    {
        Write-Host " Invalid classroom number..." -ForegroundColor Yellow
        Write-Host ""
    }
    else 
    {
        if ($confirmation -eq "Y" -or $confirmation -eq "")
        {
            #Prepare adapter for new settings#
            Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false
            Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
            Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Disabled

            #Apply new settings#
            New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $ip -PrefixLength 24 -DefaultGateway $gateway
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses ("172.30.0.42","172.30.0.43")
        }
        elseif ($confirmation -eq "N")
        {
            Write-Host " IP Configuration Terminated..." -ForegroundColor Yellow
            Write-Host ""
        }
    }
    Read-Host -Prompt "Press RETURN to go back to Menu"
}


###Net Settings function###
function NetSettings()
{
    #Check if echo requests are enabled#
    $rule = Get-NetFirewallRule -Name $ruleName
    #Check internet connection#
    $connected = Test-Connection www.google.com -Quiet

    #Display network information Begins#
    Write-Host ""
    Write-Host ""
    Write-Host " Echo Requests Enabled? " -ForegroundColor Yellow -NoNewline
    Write-Host $rule.Enabled
    Write-Host " Internet Connection Detected? " -ForegroundColor Yellow -NoNewline 
    Write-Host $connected
    Write-Host ""
    Write-Host "*********************" -ForegroundColor DarkGray -NoNewline; Write-Host "Active Network Interfaces" -ForegroundColor Cyan -NoNewline; Write-Host "*********************" -ForegroundColor DarkGray

    #Display packet information#
    $adapterStatistics = Get-NetAdapterStatistics
    $adapterStatistics | Select-Object Name, 
						     @{Name='Uni->'; Expression={$_.ReceivedUnicastPackets}},
						     @{Name='Multi->'; Expression={$_.ReceivedMulticastPackets}},
						     @{Name='Broad->'; Expression={$_.ReceivedBroadcastPackets}},
						     @{Name='Uni<-'; Expression={$_.SentUnicastPackets}},
						     @{Name='Multi<-'; Expression={$_.SentMulticastPackets}},
						     @{Name='Broad<-'; Expression={$_.SentBroadcastPackets}} | Format-Table -AutoSize -Property Name, Uni<-, Multi<-, Broad<-,
						     @{Label="Out Packets In"; Expression={"  <--  |  -->"}}, Uni->, Multi->, Broad->

    #Display connected network adapters#
    Get-NetIPConfiguration | ?{$_.NetAdapter.Status -ne "Disconnected"} -ErrorAction SilentlyContinue | fl

    #Create an object containing running processes and properties#
    $obj = @()
    Foreach($process In (Get-Process -IncludeUserName | where {$_.UserName} | select Id, ProcessName, UserName)) 
    {
	      $properties = @{ 'PID'=$process.Id;
					       'ProcessName'=$process.ProcessName;
					       'UserName'=$process.UserName;
					     }
	      $processProperties = New-Object -TypeName psobject -Property $properties
	      $obj += $processProperties
    }

    Write-Host "********************" -ForegroundColor DarkGray -NoNewline; Write-Host "Active Network Connections" -ForegroundColor Cyan -NoNewline; Write-Host "********************" -ForegroundColor DarkGray

    #Display active network connections and associated process properties#
    Get-NetTCPConnection | Where-Object {
	    $_.RemoteAddress -notin @("127.0.0.1", "0.0.0.0", "::", "::1") -and $_.State -eq "Established"
    } | Select-Object LocalPort, RemoteAddress, RemotePort, `
      @{Name="PID";Expression={$_.OwningProcess}},
      @{Name="ProcessName";Expression={($obj | Where-Object PID -eq $_.OwningProcess | Select-Object -ExpandProperty ProcessName)}},
      @{Name="UserName";Expression={($obj | Where-Object PID -eq $_.OwningProcess | Select-Object -ExpandProperty UserName)}},
      State | Sort-Object UserName, ProcessName | Format-Table -AutoSize -Property RemoteAddress, RemotePort, LocalPort, State, @{Label="  |  "; Expression={"  |  "}}, PID, ProcessName, UserName

    Read-Host -Prompt "Press RETURN to go back to Menu"
}


###NetScan function###
function NetScan()
{
    $j = 0
    $foundHosts = 0

    #Ask user for classroom number and format subnet#
    $class = Read-Host -Prompt " > What is your classroom number?"
    $subIp = "192.168." + $class

    #If input is valid continue scanning#
    if ($class -in 1..255)
    {

	    Write-Host ""
	    Write-Host " SCANNING LOCAL NETWORK....." -ForegroundColor Yellow
	    Write-Host ""

	    #Recursively search for hosts on the local network#
	    1..254 | ForEach-Object {
		    $IPAddress = "$subIp.$_"
		    $j+= 100/254
		    $result = Test-Connection -ComputerName $IPAddress -Count 1 -ErrorAction SilentlyContinue
		    #Display progress bar#
		    Write-Progress -Activity "Search in Progress" -Status ("{0:F1}% Complete. Currently scanning $IPAddress" -f $j) -PercentComplete $j

		    #If host is found, then display information#
		    if ($result)
		    {
			    #Try to resolve hostname for discovered Ip#
			    try
			    {
				    $hostName = Resolve-DnsName $IPAddress -ErrorAction Stop | Select-Object -ExpandProperty NameHost
			    }
			    catch
			    {
				    $hostName = 'Unknown host'
			    }
			    Write-Host " $hostName" -ForegroundColor Green -NoNewline
			    Write-Host " found at" -ForegroundColor Yellow -NoNewline
			    Write-Host " $IPAddress" -ForegroundColor DarkCyan
			    $foundHosts += 1
		    }
	    }
	    #Reset progress bar#
	    Write-Progress -Activity "Search in Progress" -Completed $true
    }
    Write-Host ""
    Read-Host -Prompt "$foundHosts hosts found. Press RETURN to go back to Menu"
}


###Map Studata function - Work in Progress###
function MapStudata()
{
    #Create an array of already used drive letters#
    $driveletters = (Get-PSDrive -PSProvider FileSystem).Name

    #Ask user for info#
    Write-Host ""
    $username = Read-Host -Prompt " > OTC Username"
    $password = Read-Host -Prompt " > Password"
    $studataLetter = Read-Host -Prompt " > Drive Letter"
    while ($driveletters -contains $studataLetter)
    {
        Write-Host " Pick a drive letter other then $($driveletters -join ', ') for your studata drive"
        $studataLetter = Read-Host -Prompt " > Drive Letter"
    }

    #Assign drive letter to the studata drive and save credentials#
    $FQ_Command = '/c net use ' + $studataLetter + ': \\fs-studata.otc.edu\studata\iti /user:otc\' + $username + ' ' + $password + ' /persistent:Yes'
    Start-Process -FilePath "cmd.exe"  -ArgumentList $FQ_Command -Wait
    Write-Host ""
    Get-SmbConnection
    Write-Host ""
    Read-Host -Prompt "Press RETURN to go back to Menu"
}


###About Information function###
function About()
{
	#Display about information#
Write-Host "___|_1_|___|___|___|___|___|___|___|___|___|___" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "_|___|___|___|___|" -BackgroundColor DarkRed -ForegroundColor Gray -NoNewline
Write-Host "OTC Network" -BackgroundColor DarkRed -ForegroundColor Yellow -NoNewline
Write-Host "|___|___|___|___|_" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "___|___|___|_" -BackgroundColor DarkRed -ForegroundColor Gray -NoNewline
Write-Host "Configuration Utility" -BackgroundColor DarkRed -ForegroundColor Yellow -NoNewline
Write-Host "_|___|_2_|___" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "_|___|___|___|___|___|___|___|___|___|___|___|_" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "___|___|___|___|___|___|___|___|___|___|___|___" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "_|___|_3_|___|___|___|___|___|__" -BackgroundColor DarkRed -ForegroundColor Gray -NoNewline
Write-Host "Created by" -BackgroundColor DarkRed -ForegroundColor Yellow -NoNewline
Write-Host "___|_" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "___|___|___|___|___|_4_|___|___|___" -BackgroundColor DarkRed -ForegroundColor Gray -NoNewline
Write-Host "Chris Bates" -BackgroundColor DarkRed -ForegroundColor Yellow -NoNewline
Write-Host "_" -BackgroundColor DarkRed -ForegroundColor Gray
Write-Host "_|___|___|___|___|___|___|_5_|___|___|___|___|_" -BackgroundColor DarkRed -ForegroundColor Gray

	#Display other projects#
    Write-Host ""
	Write-Host "Another Brick in the Wall:" -ForegroundColor Yellow
	Write-Host " 1) Calculator" -ForegroundColor Gray
	Write-Host " 2) Eco Server Utility" -ForegroundColor Gray
	Write-Host " 3) HahaHash Algorithm " -ForegroundColor Gray
	Write-Host " 4) Eco Mods" -ForegroundColor Gray
    Write-Host " 5) Unity-powered Game" -ForegroundColor Gray
	Write-Host " 6) Back to Menu" -ForegroundColor Gray
    Write-Host ""

	#Ask user to select option and display website or exit if 5#
	$siteSelect = 0
	while ($siteSelect -notin 1..6)
	{
		$siteSelect = Read-Host -Prompt " > Select an option"
		switch ($siteSelect)
		{
			'1'
			{
				Start-Process "https://github.com/AlteredMinds/Calculator"
			}
			'2'
			{
				Start-Process "https://github.com/AlteredMinds/EcoServerUtility"
			}
			'3'
			{
				Start-Process "http://www.planet-express.delivery/hahahash.htm"
			}
			'4'
			{
				Start-Process "https://mod.io/g/eco/u/alteredminds"
			}
            '5'
			{
				Write-Host "Disclaimer: This game contains depictions of illegal activities and themes some players may find offensive and is intended for entertainment purposes only. Contact author for inquiries." -ForegroundColor Yellow
                Write-Host ""
                Read-Host -Prompt "Press RETURN to go back to Menu"
			}
		}
	}
}


###Fake Backdoor function###
function FakeBackdoor()
{
    #Display a fake installation process#
    Write-Host ""
    Write-Host 'Initializing backdoor installation process...' -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host 'Scanning system for potential vulnerabilities...' -ForegroundColor Yellow
    Start-Sleep 7
    Write-Host '[+]' -ForegroundColor Green -NoNewline; Write-Host ' Identified system vulnerability: SMBv1 Exploit (CVE-2017-0143)'
    Start-Sleep -Milliseconds 300
    Write-Host '[+]' -ForegroundColor Green -NoNewline; Write-Host ' Exploiting vulnerability to gain unauthorized access...'
    Start-Sleep 2
    Write-Host '[+]' -ForegroundColor Green -NoNewline; Write-Host ' System access gained. Proceeding to generate backdoor payload...'
    Start-Sleep -Milliseconds 350
    Write-Host '[+]' -ForegroundColor Green -NoNewline; Write-Host ' Generating backdoor payload with encoded shellcode...'
    Start-Sleep -Milliseconds 2500
    Write-Host '[+]' -ForegroundColor Green -NoNewline; Write-Host ' Backdoor payload successfully generated.'
    Start-Sleep 1
    Write-Host '[+]' -ForegroundColor Green -NoNewline; Write-Host ' Injecting payload into system processes...'

    #Display fake progress bar#
    for($x = 0; $x -lt 100; $x += 4.5)
    {
	    Write-Progress -Activity "Installing Rootkit" -Status ("$x % Complete") -PercentComplete $x
	    Start-Sleep -Milliseconds 80
    }

    #Diplay fake error message#
    Write-Host ""
    Write-Error " Installation failed: Error code 0x800F0830. The installation encountered an unrealistic error............................"
    Write-Host ""

    #Loop Just Kidding colors#
    $color = 'Yellow'
    for ($i=0; $i -le 40; $i++) 
    {
       switch($color)
       {
	    'Green'
	    {
		    $color = 'Red'
	    }
	    'Red'
	    {
		    $color = 'Yellow'
	    }
	    'Yellow'
	    {
		    $color = 'Blue'
	    }
	    'Blue'
	    {
		    $color = 'White'
	    }
	    'White'
	    {
		    $color = 'Green'
	    }
       }
       Start-Sleep -Milliseconds 100
       Write-Host -NoNewLine "`r JUST KIDDING!!!!" -ForegroundColor $color
       Write-Host " This is not real" -ForegroundColor $color -NoNewline
    }
    #Initiate dancing parrot#
    Start-Process "cmd" -ArgumentList "/c curl parrot.live" -NoNewWindow -Wait
}

############################# Main #############################

#Variables#
$easterEgg = $false
$invalid = " Please choose a valid option..."
$scriptName = $MyInvocation.MyCommand.Name
$installed = Test-Path 'C:\Program Files\WindowsPowerShell\Scripts\OTCNetConfig.ps1'
$version = 'version 1.58'
$colors = @('DarkGreen', 'Cyan', 'Magenta', 'Yellow', 'Blue', 'DarkRed')
$randomColor = "Cyan"
$ruleName = (Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*Echo Request - ICMPv4-In*' -and $_.Profile -like '*Private*'}).Name
$exit = 0

##Continue to display menu unless exit equals 1##
for ($i = 1; ($i * $exit) -lt 1; $i++)
{
    Clear-Host
        
    #Change color of menu to a new color#
    while ($currentcolor -eq $randomColor)
    {
        $randomColor = Get-Random -InputObject $colors
    }
    $currentcolor = $randomColor

    #Display Menu# 
    Write-Host "   ___  _____  ___       __     _       ___             __ _       " -ForegroundColor $currentcolor
    Write-Host "  /___\/__   \/ __\   /\ \ \___| |_    / __\___  _ __  / _(_) __ _ " -ForegroundColor $currentcolor
    Write-Host " //  //  / /\/ /     /  \/ / _ \ __|  / /  / _ \| '_ \| |_| |/ _`  |" -ForegroundColor $currentcolor
    Write-Host "/ \_//  / / / /___  / /\  /  __/ |_  / /__| (_) | | | |  _| | (_| |" -ForegroundColor $currentcolor
    Write-Host "\___/   \/  \____/  \_\ \/ \___|\__| \____/\___/|_| |_|_| |_|\__, |" -ForegroundColor $currentcolor
    Write-Host "                            " -ForegroundColor $currentcolor -NoNewline
    Write-Host "$version" -ForegroundColor Gray -NoNewline
    Write-Host "                     |___/" -ForegroundColor $currentcolor
    Write-Host " *************************" -ForegroundColor DarkGray
    Write-Host " 1) Configure Echo Requests" -ForegroundColor Gray
    Write-Host " 2) Display Network Info" -ForegroundColor Gray
    Write-Host " 3) Ip Configuration Wizard" -ForegroundColor Gray
    Write-Host " 4) Network Host Scan" -ForegroundColor Gray
    Write-Host " 5) About" -ForegroundColor Gray
    Write-Host " 6) Exit" -ForegroundColor Gray
    if ($easterEgg) {Write-Host " :) Install Backdoor" -ForegroundColor Gray}
    Write-Host " *************************" -ForegroundColor DarkGray
    $selection = Read-Host -Prompt " > Select an option"

    switch ($selection)
    {
	  ###If selection is 1 set value of echo requests###
		'1'
	    {
			EchoSetup
		}

	  ###If selection is 2 show adapter settings###
		'2'
	    {
			NetSettings
		}

	  ###If selection is 3 enter Ip config wizard###
		'3'
	    {
			IpSetup
		}

	  ###If selection is 4 then scan for other local hosts###
		'4'
	    {
			NetScan
		}

	  ###If selection is 5 then display about information###
		'5'
	    {
            About
		}

	  ###If selection is 6 then exit###
		'6'
	    {
			#Signal program to exit#
			$exit = 1
		}
      ###Install Backdoor!!!!1!11101101010L0LoLOL###
		':'
	    {
			if ($easterEgg) {FakeBackdoor}
		}
    }
}
#Thank you, Come agian#
exit