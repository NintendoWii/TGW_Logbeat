function Detect-PowerlessShell{
    function build-class{
        $outputclass= [pscustomobject][ordered]@{
            IP= "Null"
            Hostname= $env:COMPUTERNAME
            DateCollected= $null
            TimeGenerated= "Null"
            Source= "Detect-PowerlessShell"
            Indicator= $null
            Location= $null
        }
    return $outputclass
    }  
    
    $output= @()    

    #Powerless artifact file 1
    $artifactfile1= get-childitem -path "C:\Windows\Temp\" -force -Recurse | where {$_.name -like "*Report*" -and $_.Attributes -like "*Archive*"}
       
    if ($artifactfile1){
        foreach ($a in $artifactfile1){
            $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
            $results= build-class
            $results.datecollected= $date
            $results.indicator= $($a.fullname)
            $results.location= "Filesystem"
            $output+= $results | ConvertTo-Json
        }
    }
    
    #Powerless artifact file 1        
    $artifactfile2= get-childitem -path "C:\Windows\Temp\" -force -Recurse | where {$_.name -like "*cup.tmp*" -and $_.Attributes -like "*Archive*"}
        
    if ($artifactfile2){
        foreach ($a in $artifactfile2){
            $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
            $results= build-class
            $results.datecollected= $date
            $results.indicator= $($a.fullname)
            $results.location= "Filesystem"
            $output+= $results | ConvertTo-Json
        }
    }
        
    #powerless strings in Powershell logs
    $strings= @()
    $str1= "'" + 'Start-process powershell -win 1 -argumentlist' + ' "' + "sleep 1; Get-ChildItem -path"
    $str1= $str1 + ' `' + "'" + '$p`'+ "'" + ' | remove-item"' + "'"
    $strings+= $str1
    $strings+= 'function Write-ExtractionProgress'
    $strings+= 'Find-ExternalOutputFolder'
    $strings+= 'private static IntPtr hookId = IntPtr.Zero'
    $strings+= 'Add-Content -Path $Profile.CurrentUserAllHosts '
    
    $PowershellLogs= $(Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | where {$_.id -eq 4104})
    $userid= $($env:USERNAME | Get-LocalUser).sid.value

    foreach ($p in $PowershellLogs){
        foreach ($s in $strings){
            if ($p.message | select-string "$s"){
                if ($p.UserId.value -ne $userid){
                    $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
                    $results= build-class
                    $results.datecollected= $date
                    $results.timegenerated= $p.TimeCreated
                    $results.indicator= $s
                    $results.location= "Powershell Record ID $($p.recordid)"
                    $output+= $results | ConvertTo-Json
                }
            }
        }
    }
    
    #Chromium F.exe, sou.exe, rsf.exe, dll.dll, windowsprocesses.exe
    #search process list, eventlog 4688 and prefetch
    $procs=@("chromiumf.exe","chromium f.exe","sou.exe","rsf.exe","windowsprocesses.exe","dll.dll")
    
    foreach ($p in $procs){
        #in processes
        if ($p -eq "dll.dll"){
            get-process | % {if ($($_.modules).modulename -eq "dll.dll"){
                    $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
                    $results= build-class
                    $results.datecollected= $date
                    $results.indicator= $_.path
                    $results.location= "Running_processes"
                    $output+= $results | ConvertTo-Json
                    }
                }
        }
    
        if ($p -ne "dll.dll"){
            $in_proc= Get-WmiObject -Class win32_process | where {$_.name -eq "$p"}
            if ($in_proc){
                $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
                $results= build-class
                $results.datecollected= $date
                $results.indicator= $p
                $results.location= "Running_processes"
                $output+= $results | ConvertTo-Json
            }

            #in Logs
            $in_4688= $(Get-EventLog -LogName security -InstanceId 4688 -ErrorAction SilentlyContinue) | % {if ($_.ReplacementStrings[5] -like "*$p*"){$_}}
            if ($in_4688){
                $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
                $results= build-class
                $results.datecollected= $date
                $results.indicator= $p
                $results.location= "Eventlog_4688"
                $output+= $results | ConvertTo-Json
            }

            #in Prefetch
            $in_pf= Get-ChildItem -Path C:\windows\prefetch | where {$_.name -like "*$p*"}
            if ($in_pf){
                    $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
                    $results= build-class
                    $results.datecollected= $date
                    $results.indicator= $p
                    $results.location= "Prefetch"
                    $output+= $results | ConvertTo-Json
            }
        }
    }
    
    #non powershell, explorer or cmd exe with a child of powershell (Reveals ps1 2 exe was potentially used to compile)
    $processes= Get-WmiObject -Class win32_process
    
    foreach ($p in $processes){
        $parent= $(Get-WmiObject -Class win32_process | where {$_.ProcessId -eq $p.ParentProcessId}).name
        $child=  $p.Name
    
        if ($parent -ne "powershell.exe" -and $parent -ne "Powershell_ise.exe" -and $parent -ne "Cmd.exe" -and $parent -ne "Explorer.exe" -and $child -like "*powershell*"){
            $date= (Get-Date -Format "dd-MMM-yyyy HH:mm").Split(":") -join ""
            $results= build-class
            $results.datecollected= $date
            $results.indicator= "Parent:$parent-Child:$child"
            $results.location= "Running_processes"
            $output+= $results | ConvertTo-Json
        }
    }    

if (!$output){
    $results= build-class
    $results.datecollected= $date
    $results.indicator= "Null"
    $results.location= "Null"
    $output+= $results | ConvertTo-Json
}

$output | ConvertFrom-Json | convertto-csv -NoTypeInformation
}

#Detect-PowerlessShell
Export-ModuleMember -Function Detect-PowerlessShell