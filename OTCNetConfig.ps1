<#
Author: Christopher Bates
Date: 2-24
Description: Small utility designed for automating tasks and network mapping on a OTC workstation.
Version: 1.27
Contact: cb0988836@otc.edu
#>



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

#Ip Setup function#
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

    #Get all adapters#
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
    if ($class -eq "" -or [int]$class -notin 1..255 -or $computer -eq "" -or [int]$computer -notin 1..255)
    {
        Write-Host " Invalid class number..." -ForegroundColor Yellow
        Write-Host ""
    }
    else 
    {
        if ($confirmation -eq "Y" -or $confirmation -eq "")
        {
            #Prepare adapter for new settings#
            Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false
            Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false
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


#Variables#
$invalid = " Please choose a valid option..."
$scriptName = $MyInvocation.MyCommand.Name
$installed = Test-Path 'C:\Program Files\WindowsPowerShell\Scripts\OTCNetConfig.ps1'
$version = 'version 1.27'
$colors = @('DarkGreen', 'Cyan', 'Magenta', 'Yellow', 'Blue', 'DarkRed')
$ruleName = (Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*Echo Request - ICMPv4-In*' -and $_.Profile -like '*Private*'}).Name
$exit = 0

##BEGIN MENU##
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
    Write-Host " 5) Install Backdoor" -ForegroundColor Gray
    Write-Host " 6) About" -ForegroundColor Gray
    Write-Host " 7) Exit" -ForegroundColor Gray
    Write-Host " *************************" -ForegroundColor DarkGray
    $selection = Read-Host -Prompt " > Select an option"

        ###If selection is valid  and not exiting, continue with selection###
        if ($selection -ge "1" -and $selection -le "7" -and $exit -lt 1)
        {
          ###If selection is 1 set value of echo requests###
            if($selection -eq "1")
            {
                #Ask user whether to disable or enable echo requests#
                Write-Host ""
                Write-Host "     1) Enable Echo Requests" -ForegroundColor Gray
                Write-Host "     2) Disable Echo Requests" -ForegroundColor Gray
                $selection2 = Read-Host -Prompt "     > Select an option"

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
                if ($selection2 -le "2" -and $selection2 -ne "")
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

          ###If selection is 2 show adapter settings###
            elseif($selection -eq "2")
            {
                #Check if echo requests are enabled#
                $rule = Get-NetFirewallRule -Name $ruleName
                #Check internet connection#
                $connected = Test-Connection www.google.com -Quiet

                #Display network information Begins#
                Write-Host ""
                Write-Host ""
                Write-Host " Echo Requests Enabled?" $rule.Enabled -ForegroundColor Yellow 
                Write-Host " Internet Connection Detected?" $connected -ForegroundColor Yellow 
                Write-Host ""
                Write-Host "*********************" -ForegroundColor DarkGray -NoNewline; Write-Host "Active Network Interfaces" -ForegroundColor Cyan -NoNewline; Write-Host "*********************" -ForegroundColor DarkGray
                
                #Display packet information#
                $adapterStatistics = Get-NetAdapterStatistics
                $adapterStatistics | Select-Object Name, 
                                         @{Name='ReceivedPackets'; Expression={'    -->'}},
                                         @{Name='Uni->'; Expression={$_.ReceivedUnicastPackets}},
                                         @{Name='Multi->'; Expression={$_.ReceivedMulticastPackets}},
                                         @{Name='Broad->'; Expression={$_.ReceivedBroadcastPackets}},
                                         @{Name='SentPackets'; Expression={'    <--'}},
                                         @{Name='Uni<-'; Expression={$_.SentUnicastPackets}},
                                         @{Name='Multi<-'; Expression={$_.SentMulticastPackets}},
                                         @{Name='Broad<-'; Expression={$_.SentBroadcastPackets}} | Format-Table -AutoSize -Property Name, ReceivedPackets, Uni->, Multi->, Broad->,
                                         @{Label="  |  "; Expression={"  |  "}}, SentPackets, Uni<-, Multi<-, Broad<-
                
                #Display connected network adapters#
                Get-NetIPConfiguration | ?{$_.NetAdapter.Status -ne "Disconnected"} | fl

                #Create an object containing running processes and properties#
                $obj = @()
                Foreach($process In (Get-Process -IncludeUserName | where {$_.UserName} | `
                  select Id, ProcessName, UserName)) {
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

          ###If selection is 3 enter ip setup###
            elseif($selection -eq "3")
            {
                IpSetup
            }

          ###If selection is 4 then scan for other local devices###
            elseif($selection -eq "4")
            {
                $j = 0
                $foundHosts = 0

                #Ask user for classroom number and formate subnet#
                $class = Read-Host -Prompt " > What is your classroom number?"
                $subIp = "192.168." + $class
                
                #If input is not blank continue scanning#
                if ($class -ne "")
                {
                    Write-Host ""
                    Write-Host " SCANNING LOCAL NETWORK....."
                    Write-Host ""
            
                    #Recursively search for hosts on the local network#
                    1..254 | ForEach-Object {
                        $IPAddress = "$subIp.$_"
                        $j+= 0.393700787
                        $result = Test-Connection -ComputerName $IPAddress -Count 1 -ErrorAction SilentlyContinue
                        Write-Progress -Activity "Search in Progress" -Status ("{0:F1} % Complete. Currently scanning $IPAddress" -f $j) -PercentComplete $j

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
                }
                Read-Host -Prompt "$foundHosts hosts found. Press RETURN to go back to Menu"
            }

          ###DONT DO IT !!!!!!!!!!!!!111111110110101010L0L0LOLOL###
            elseif($selection -eq "5")
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
                for($i = 0; $i -lt 100; $i += 4.5)
                {
                    Write-Progress -Activity "Installing Rootkit" -Status ("$i% Complete" -f $i) -PercentComplete $i
                    Start-Sleep -Milliseconds 80
                }

                #Diplay fake error message#
                Write-Host ""
                Write-Error " Installation failed: Error code 0x800F0830. The installation encountered an unrealistic error............................"
                Write-Host ""

                #Loop Just Kidding and change colors#
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

          ###If selection is 6 then go to website###
            elseif($selection -eq "6")
            {
                #Open browser and display website#
                Start-Process "http://www.planet-express.delivery"
            }

          ###If selection is 7 then exit###
            elseif($selection -eq "7")
            {
                #Signal program to exit#
                $exit = 1
            }
        }

}
#Thank you, Come agian#
exit