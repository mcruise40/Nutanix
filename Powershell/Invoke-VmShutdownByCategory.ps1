<#
.SYNOPSIS
Shut down or power off VMs based on category in Prism Central
.DESCRIPTION
Automates the process of shutting down or powering off virtual machines in Nutanix Prism Central, as it
targets VMs based on the specified category.
.PARAMETER nxIP
IP address of the Nutanix Prism Central you're making a connection too.
.PARAMETER nxUser
Username for the connection to the Nutanix Prism Central
.PARAMETER nxPassword
Password for the connection to the Nutanix Prism Central
.PARAMETER clusterName
Defines to stop VMs only on a particular cluster. Otherweise, VMs from all cluster will be stopped!
.PARAMETER categoryName
Name of the category, which contains the values applied to the VMs to shutdown
.PARAMETER categoryValue
Value of the category that are applied to VMs to stop
.PARAMETER skipCertificateCheck
Disable certificate check for API calls (works only with PowerShell 7+)
.PARAMETER parallel
Shutdown VMs simultaneously
.PARAMETER quiet
Don't ask for confirmation to shut down VMs
.EXAMPLE
PS C:\PSScript > .\Invoke-VmShutdownByCategory.ps1 -nxIP 10.0.200.100 -nxUser admin -nxPassword nutanix/4u -skipCertificateCheck -categoryName ShutdownGroup -categoryValue A -clusterName dc01-cl0
.INPUTS
None.  You cannot pipe objects to this script.
.OUTPUTS
No objects are output from this script.
.NOTES
NAME: Invoke-VmShutdownByCategory
VERSION: 1.0
Author: Andy Kruesi, Ceruno AG
Basend on Nutanix Inventory Script by author: Manoj Mone, Nutanix (https://github.com/manoj-mone/Nutanix/tree/main/Powershell)
and Kees Baggerman
Created On: December 21, 2023
#>

# Setting parameters for the connection
[CmdletBinding(SupportsShouldProcess = $False, ConfirmImpact = "None") ]
Param(
    # Nutanix cluster IP address
    [Parameter(Mandatory = $true)]
    [Alias('Hostname')] [string] $nxIP,

    # Nutanix cluster username
    [Parameter(Mandatory = $true)]
    [Alias('User')] [string] $nxUser,

    # Nutanix cluster password
    [Parameter(Mandatory = $true)]
    [Alias('Password')] [string] $nxPassword,

    # Nutanix cluster name, if not defined it run on all clusters!
    [Parameter(Mandatory = $false)]
    [string] $clusterName,    

    # Name of category to look for value
    [Parameter(Mandatory = $true)]
    [string] $categoryName,

    # Value of category
    [Parameter(Mandatory = $true)]
    [string] $categoryValue,

    # Certificate check for API calls
    [Parameter(Mandatory = $false)]
    [switch] $skipCertificateCheck = $false,

    # Parallel mode, shutdown VMs simultaneously
    [Parameter(Mandatory = $false)]
    [switch] $parallel = $false,

    # Quiet mode
    [Parameter(Mandatory = $false)]
    [switch] $quiet = $false
)

# Converting the password to a secure string
#$nxPasswordSec = ConvertTo-SecureString $nxPassword -AsPlainText -Force
Function Write-Log {
    <#
.Synopsis
Write logs for debugging purposes
.Description
This function writes logs based on the message including a time stamp for debugging purposes.
#>
    param (
        $message,
        $sev = "INFO"
    )
    if ($sev -eq "INFO") {
        write-host "$(get-date -format "hh:mm:ss") | INFO | $message"
    }
    elseif ($sev -eq "WARN") {
        write-host "$(get-date -format "hh:mm:ss") | WARN | $message" -ForegroundColor Yellow
    }
    elseif ($sev -eq "ERROR") {
        write-host "$(get-date -format "hh:mm:ss") | ERROR | $message" -ForegroundColor Red
    }
    elseif ($sev -eq "CHAPTER") {
        write-host "`n`n### $message`n`n"
    }
}

$debug = 2
Function Get-Clusters {
    <#
    .Synopsis
    This function will collect the clusters within the specified Prism Central.
    .Description
    This function will collect the hosts within the specified cluster using REST API call based on Invoke-RestMethod
    #>
    Param (
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    #$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440//api/nutanix/v3/clusters/list"
    $Payload = @{
        kind   = "cluster"
        offset = 0
        length = 200
    } 
    $JSON = $Payload | convertto-json

    $params = @{
        Uri                  = $URL
        Method               = 'Post'
        Body                 = $JSON
        ContentType          = 'application/json'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }
    try {
        $task = Invoke-RestMethod @params
    }
    catch {
        $saved_error = $_.Exception.Message
        Write-Log -message "Error - Please check your credentials - $($saved_error)"
        exit

    }
    Write-Log -message "Found $($task.entities.count) clusters in this Prism Central."
    Return $task
} 
Function Get-Hosts {
    <#
.Synopsis
This function will collect the hosts within the specified cluster.
.Description
This function will collect the hosts within the specified cluster using REST API call based on Invoke-RestMethod
#>
    Param (
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    #$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440/api/nutanix/v3/hosts/list"
    $Payload = @{
        kind   = "host"
        offset = 0
        length = 2500
    } 
    $JSON = $Payload | convertto-json

    $params = @{
        Uri                  = $URL
        Method               = 'Post'
        Body                 = $JSON
        ContentType          = 'application/json'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }
    try {
        $task = Invoke-RestMethod @params
    }
    catch {
        Write-Log -message "Error extracting Host Information"
    }
    Write-Log -message "Found $($task.entities.count) hosts on this Prism Central."
    Return $task
} 
Function Get-VMs {
    <#
.Synopsis
This function will collect the VMs within the specified cluster.
.Description
This function will collect the VMs within the specified cluster using REST API call based on Invoke-RestMethod
#>
    Param (
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    #$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

    $headers = @{ Authorization = "Basic $encodedCredentials" }
    Write-Log -message "Executing VM List Query"
    $URL = "https://$($nxIP):9440/api/nutanix/v3/vms/list"
    $Payload = @{
        kind   = "vm"
        offset = 0
        length = 999
    } 
    $JSON = $Payload | convertto-json

    $params = @{
        Uri                  = $URL
        Method               = 'Post'
        Body                 = $JSON
        ContentType          = 'application/json'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }
    try {
        $task = Invoke-RestMethod @params
    }
    catch {
        Write-Log -message "Error extracting VM Information"
    }
    Write-Log -message "Found $($task.entities.count) VMs."
    Return $task
} 
Function Get-DetailVM {
    <#
.Synopsis
This function will collect the speficics of the VM we've specified using the Get-VMs function as input.
.Description
This function will collect the speficics of the VM we've specified using the Get-VMs function as input using REST API call based on Invoke-RestMethod
#>
    Param (
        [string] $uuid,
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    #$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440/api/nutanix/v3/vms/$($uuid)"

    $params = @{
        Uri                  = $URL
        Method               = 'Get'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }

    try {
        $task = Invoke-RestMethod @params
    }
    catch {
        Write-Log -message "Error extracting VM details for VM with uuid $($uuid)"
        # $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers;
    }
    Return $task
} 
Function Get-DetailHosts {
    Param (
        [string] $uuid,
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    #$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440/api/nutanix/v3/hosts/$($uuid)"

    $params = @{
        Uri                  = $URL
        Method               = 'Get'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }

    try {
        $task = Invoke-RestMethod @params
    }
    catch {
        Write-Log -message "Error extracting details of Host having uuid $($uuid)"
    }  
    Return $task
}
Function Stop-VmGracefully {
    <#
.Synopsis
This function will try to shutdown a VM.
.Description
This function will send an ACPI shutdown command to the VM using REST API call based on Invoke-RestMethod
#>
    Param (
        [string] $uuid,
        [switch] $quiet = $false,
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))

    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440/api/nutanix/v3/vms/$($uuid)/acpi_shutdown"

    $taskUuid = (New-Guid).Guid

    $Payload = @{
        task_uuid = $taskUuid
    } 
    $JSON = $Payload | convertto-json

    $params = @{
        Uri                  = $URL
        Method               = 'Post'
        Body                 = $JSON
        ContentType          = 'application/json'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }

    if (-not $quiet) {
        # Initialize userInput
        $userInput = $null

        # Loop until the user enters a valid option
        while ($userInput -notmatch '^[YN]$') {
            $userInput = Read-Host "Are you sure to shutdown VM? (Y)es, (N)o"
        
            # Convert to uppercase for consistency
            $userInput = $userInput.ToUpper()

            # Check if the input is not 'A', 'L', or 'C'
            if ($userInput -notmatch '^[YN]$') {
                Write-Output "Invalid input. Please enter 'Y' for Yes, 'N' for No and to cancel."
            }
        }
    }

    # Proceed based on the user input
    if ($userInput -eq 'N') {
        # Exit script
        Write-Log "Operation cancelled by the user."
        break
    }
    else {
        try {
            $task = Invoke-RestMethod @params
        }
        catch {
            Write-Log -message "Error execute shutdown" -sev ERROR
        }
        Return $task
    }


}
Function Get-TaskState {
    <#
.Synopsis
This function will return the task state.
.Description
This function will retrieve a task state of the specified task using REST API call based on Invoke-RestMethod
#>
    Param (
        [string] $uuid,
        [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))

    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440/api/nutanix/v3/tasks/poll"


    $Payload = @{
        poll_timeout_seconds = 5
        task_uuid_list       = @($uuid)
    } 
    $JSON = $Payload | ConvertTo-Json

    $params = @{
        Uri                  = $URL
        Method               = 'Post'
        Body                 = $JSON
        ContentType          = 'application/json'
        Headers              = $headers
        skipCertificateCheck = $skipCertificateCheck
    }

    try {
        $task = Invoke-RestMethod @params
    }
    catch {
        Write-Log -message "Error retrieving task state" -sev ERROR
    }
    Return $task.status
}

#region Main

#region Step 1 - Collect Cluster Information
$pcClusters = Get-Clusters -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug
$ClusterFullReport = @()
Foreach ($entity in $pcClusters.entities) {
    Write-Log -message "Collecting information about Cluster $($entity.status.name) with uuid $($entity.metadata.uuid)"            
    $props = [ordered]@{
        "Cluster Name" = $entity.status.name
        "Cluster uuid" = $entity.metadata.uuid
    }
    $ClusterReportobject = New-Object PSObject -Property $props
    $Clusterfullreport += $ClusterReportobject
}
#endregion

#region Step 2 - Collect VM information
$vms = Get-VMs -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug

if ($clusterName) {
    $vmsToProcess = $vms.entities | Where-Object { $_.metadata.categories.$categoryName -eq $categoryValue -and $_.status.cluster_reference.name -eq $clusterName }
}
else {
    $vmsToProcess = $vms.entities | Where-Object { $_.metadata.categories.$categoryName -eq $categoryValue }
}


if ($vmsToProcess) {

    Write-Log -message "Grabbing VM information"

    $VmFullReport = @()
    foreach ($vm in $vmsToProcess) {
        Write-Log -message "Currently grabbing information about VM $($vm.spec.Name) (UUID: $($vm.metadata.uuid))"
        $myvmdetails = Get-DetailVM -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug -uuid $vm.metadata.uuid
        if ($null -eq ($myvmdetails.status.resources.host_reference.uuid)) {
            $hostname = ""
        }
        else {
            $myhostdetails = Get-DetailHosts -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug -uuid $myvmdetails.status.resources.host_reference.uuid
            $hostname = $myhostdetails.status.name
                
        }

        if ($myvmdetails.status.cluster_reference.name -eq $clusterName) {
            $props = [ordered]@{
                "VM Name"                  = $vm.spec.Name
                "VM uuid"                  = $vm.metadata.uuid
                "VM Host"                  = $hostname
                "VM Host uuid"             = $myvmdetails.status.resources.host_reference.uuid
                "Cluster Name"             = $myvmdetails.status.cluster_reference.name
                "Cluster UUID"             = $myvmdetails.spec.cluster_reference.uuid
                "Power State"              = $myvmdetails.status.resources.power_state
                "Network Name"             = $myvmdetails.status.resources.nic_list.subnet_reference.name
                "IP Address(es)"           = $myvmdetails.status.resources.nic_list.ip_endpoint_list.ip -join ","
                "Number of Cores"          = $myvmdetails.spec.resources.num_sockets
                "Number of vCPUs per core" = $myvmdetails.spec.resources.num_vcpus_per_socket
                "Memory in MB"             = $myvmdetails.spec.resources.memory_size_mib
                "VM Time Zone"             = $myvmdetails.spec.resources.hardware_clock_timezone
            } #End properties
            $Reportobject = New-Object PSObject -Property $props
            $VmFullReport += $Reportobject
        }
    }
        
    Write-Host "Found VMs below. All VMs with power state ON will be shutting down:"
    $VmFullReport | Format-Table "VM Name", "Power State", "Network Name", "IP Address(es)", "Cluster Name", "VM Host", "Number of Cores", "Number of vCPUs per core", "Memory in MB" -AutoSize
#endregion

#region Step 3 - Ask for confirmation
    if (-not $quiet) {
        # Initialize userInput
        $userInput = $null
    
        # Loop until the user enters a valid option
        while ($userInput -notmatch '^[YN]$') {
            $userInput = Read-Host "Do you want to proceed? (Y)es, (N)o"
            
            # Convert to uppercase for consistency
            $userInput = $userInput.ToUpper()
    
            # Check if the input is not 'A', 'L', or 'C'
            if ($userInput -notmatch '^[YN]$') {
                Write-Output "Invalid input. Please enter 'Y' for Yes, 'N' for No and to cancel."
            }
        }
    }
#endregion

#region Step 4 - VM shut down
    # Proceed based on the user input or if quiet-mode is enabled
    if ($userInput -eq 'Y' -or $quiet) {
        Write-Log "Proceeding to shut down VMs..."
        $VmsOn = $VmFullReport | Where-Object { $_."Power State" -eq "ON" }
        # Attempt to shut down each VM that has power state 'ON'
        do {
            # if parameter 'Parallel' is set, shutdown tasks will run simultaneously
            if ($Parallel) {
                # Store the function in strings to make it available in the ThreadJobs
                $funcDefWriteLog         = ${function:Write-Log}.ToString()
                $funcDefStopVmGracefully = ${function:Stop-VmGracefully}.ToString()
                $funcDefGetTaskState     = ${function:Get-TaskState}.ToString()
                $funcDefGetDetailVM      = ${function:Get-DetailVM}.ToString()

                $jobs = foreach ($vm in $VmsOn) {
                    Start-ThreadJob -Name $vm."VM Name" -ArgumentList $vm, $nxIP, $nxPassword, $nxUser, $debug -ScriptBlock {
                        param($vm, $nxIP, $nxPassword, $nxUser, $debug)
                        ${function:Write-Log}         = $using:funcDefWriteLog
                        ${function:Stop-VmGracefully} = $using:funcDefStopVmGracefully
                        ${function:Get-TaskState}     = $using:funcDefGetTaskState
                        ${function:Get-DetailVM}      = $using:funcDefGetDetailVM

                        Write-Log "Shutdown VM $($vm."VM Name")"
                        do {
                            # Send shutdown command
                            $task = Stop-VmGracefully -uuid $vm."VM uuid" -quiet
                            do {
                                # Check task state
                                $taskState = ""
                                $taskState = Get-TaskState -Uuid $task.task_uuid
                                Start-Sleep -Seconds 5
                            } while ([string]::IsNullOrEmpty($taskState))
                            Write-Log -message "The task has status $($taskState)."
        
                            # Set timeout based on task state result
                            switch ($taskState) {
                                "SUCCEEDED" { 
                                    $timeout = New-TimeSpan -Minutes 2
                                }
                                "FAILED" {
                                    $timeout = New-TimeSpan -Seconds 10
                                }
                                Default {
                                    $timeout = New-TimeSpan -Seconds 15
                                }
                            }
        
                            # Update VM power state
                            $sw = [diagnostics.stopwatch]::StartNew()
                            do {
                                $vm."Power State" = (Get-DetailVM -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug -uuid $vm."VM uuid").status.resources.power_state
                                Write-Log -message "Power state for VM $($vm."VM Name") is $($vm."Power State")."
                                if ($vm."Power State" -eq "OFF") {
                                    break
                                }
                                Write-Log -message "Timeout: $([math]::Round($sw.elapsed.TotalSeconds)) of $([math]::Round($timeout.TotalSeconds)) seconds elapsed."
                                Start-Sleep -Seconds 10
                            } while ($sw.elapsed -lt $timeout)
                            Clear-Variable -Name sw
                        } while ($vm."Power State" -eq "ON")
                    } -ThrottleLimit 5
                }

                Write-Host 'Waiting for jobs to complete...' -NoNewLine
                while ($jobs | Where-Object State -in 'Running', 'NotStarted') {
                    Write-Host . -NoNewline
                    Start-Sleep -Milliseconds 200
                }
                Write-Host finished.

                $jobs | Wait-Job -Timeout 90
                $result = $jobs | Receive-Job -AutoRemoveJob -Wait
                $result
            }
            else {
                # if 'Parallel' parameter was not set, the script will sequentially shut down the VMs
                $VmsOn | Foreach-Object {
                    $vm = $_
                    write-log "Shutdown VM $($vm."VM Name")"
                    do {
                        # Send shutdown command
                        $task = Stop-VmGracefully -uuid $vm."VM uuid" -quiet
                        do {
                            # Check task state
                            $taskState = ""
                            $taskState = Get-TaskState -Uuid $task.task_uuid
                            Start-Sleep -Seconds 5
                        } while ([string]::IsNullOrEmpty($taskState))
                        Write-Log -message "The task has status $($taskState)."

                        # Set timeout based on task state result
                        switch ($taskState) {
                            "SUCCEEDED" { 
                                $timeout = New-TimeSpan -Minutes 2
                            }
                            "FAILED" {
                                $timeout = New-TimeSpan -Seconds 10
                            }
                            Default {
                                $timeout = New-TimeSpan -Seconds 15
                            }
                        }

                        # Update VM power state
                        $sw = [diagnostics.stopwatch]::StartNew()
                        do {
                            $vm."Power State" = (Get-DetailVM -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug -uuid $vm."VM uuid").status.resources.power_state
                            Write-Log -message "Power state for VM $($vm."VM Name") is $($vm."Power State")."
                            if ($vm."Power State" -eq "OFF") {
                                break
                            }
                            Write-Log -message "Timeout: $([math]::Round($sw.elapsed.TotalSeconds)) of $([math]::Round($timeout.TotalSeconds)) seconds elapsed."
                            Start-Sleep -Seconds 10
                        } while ($sw.elapsed -lt $timeout)
                        Clear-Variable -Name sw
                    } while ($vm."Power State" -eq "ON")
                }
            }
            $VmFullReport | Format-Table "VM Name", "Power State", "Network Name", "IP Address(es)", "Cluster Name", "VM Host", "Number of Cores", "Number of vCPUs per core", "Memory in MB" -AutoSize
            # Script ends when all VMs are 'OFF'
        } while ($VmsOn | Where-Object { $_."Power State" -eq 'ON' })
    }
    else {
        # Exit script
        Write-Log "Operation cancelled by the user. Script exited."
        exit
    }


}
else {
    Write-Log -message "No VMs found in Category $($categoryName) with Value $($categoryValue). Script exited." -sev WARN
}



# Disconnecting from the Nutanix Cluster
Write-Log -message "Closing the connection to the Nutanix cluster $($nxIP)"
Write-Log -message "Processing Complete"

#endregion