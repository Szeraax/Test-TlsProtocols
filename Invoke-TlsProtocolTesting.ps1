<#
.DESCRIPTION
    Accepts a list of servers, ports, and protocol names to test on remote hosts.
    Expects Test-TlsProtocols to already be loaded or available (looks in script dir by default).


.NOTES
    Special thanks to TechnologyAnimal for making this great tool. -Szeraax

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

.LINK
    https://github.com/TechnologyAnimal/Test-TlsProtocols

.PARAMETER InputObject
    Array of objects for the list of servers, ports, and protocol names (any of them can be space delimited to run multiple across other fields) to test. Can be piped from an Import-Csv cmdlet easily.
    Expects the following case-insensitive property names: Host, Port, Protocol

.PARAMETER DestinationPath
    If specified, output to path instead of Write-Output.
    If specified, any results in DestinationPath and all 'frozen' scans located in $WorkingDirectory will be skipped that come through input. Force running on all inputs via -Force

.PARAMETER Force
    Switch to force testing all input rows and overwrite existing DestinationPath.

.PARAMETER WorkingDirectory
    Where to store temporary working files. Defaults to $PSScriptDir.

.PARAMETER DisableParallel
        Defaults to use foreach -Parallel in pwsh7 if available. Use this switch to not do use that capability

.PARAMETER Taskers
    Computers to distribute the load between. Defaults to localhost only.
#>

[CmdletBinding(
    SupportsShouldProcess
)]
param (
    [Parameter(Mandatory)]
    $InputObject,
    [string]$DestinationPath,
    [switch]$Force,
    [string]$WorkingDirectory,
    [switch]$DisableParallel
)

begin {
    if (-not $PSBoundParameters.WorkingDirectory) { $WorkingDirectory = $PSScriptRoot }
    [Environment]::CurrentDirectory = $PSScriptRoot
    $DestinationPath = [IO.path]::GetFullPath($DestinationPath)
    $DestinationPath
    if ($Force.IsPresent) {
        if (Test-Path $DestinationPath) {
            Remove-Item $DestinationPath
        }
    }

    Get-ChildItem "$WorkingDirectory\*.lock" | ForEach-Object {
        Write-Verbose "Removing previous scan lockfile: $($PSItem.FullName)"
        Remove-Item $_.FullName
    }

    $SupportedProtocols = ([System.Security.Authentication.SslProtocols]).GetEnumValues().Where{ $_ -ne 'Default' -and $_ -ne 'None' }
    Write-Verbose "Supported tls protocols:"
    $SupportedProtocols | ForEach-Object { Write-Verbose "$_" }


    # This will get run in the seperate runspace as a foreach scriptblock
    $Func = {
        $WorkingDirectory = "C:\users\devin\git\Test-TlsProtocols"
        $Param = @{ }

        # Allow passing string[] or objects, but fail if neither.
        if ($PSItem.Server) { $Param.Add("Server", $PSItem.Server) }
        elseif (@($PSItem)[0] -is "String") { $Param.Add("Server", $PSItem) }
        else { Write-Error -ErrorAction Stop "Unable to determine argument 'server'." }

        if ($PSItem.Port) { $Param.Add("Port", $PSItem.Port) }
        if ($PSItem.Protocol) { $Param.Add("Protocol", $PSItem.Protocol) }
        $TempFileName = "$WorkingDirectory\{0} {1}.lock" -f $Param.Server, $Param.Port, $Param.Protocol
        Get-date -f s | out-file $TempFileName
        Test-TlsProtocols -Server google.com

        # Test-TlsProtocols @Param
        Remove-Item $TempFileName
    }

    # Allow you to use older versions of powershell (or manually ):
    if ($PSVersionTable.PSVersion.Major -lt 7 -or $DisableParallel) {
        $Param = @{
            Process = $Func
        }
    }
    else {
        $Param = @{
            Parallel = $Func
        }
    }


    $List = [System.Collections.Generic.List[System.Object]]::New()
}

process {
    foreach ($Item in $InputObject) {
        $List.Add($Item)
    }
}

end {
    # Seperate the worker into another runspace so we can kill it and restart as needed
    # We need to get this function from the current runspace and add it to a session state that will get loaded
    $FunctionName = "Test-TlsProtocols"
    $FunctionDefinition = Get-Content function:\$FunctionName

    $FunctionEntry = [Management.Automation.Runspaces.SessionStateFunctionEntry]::new($FunctionName, $FunctionDefinition)
    $InitialSessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $InitialSessionState.Commands.Add($FunctionEntry)

    $PowerShell = [powershell]::Create($InitialSessionState)
    $ScriptParam = @{
        Param              = $Param
        SupportedProtocols = $SupportedProtocols
        DestinationPath    = $DestinationPath
        WorkingDirectory   = "C:\users\devin\git\Test-TlsProtocols"
    }
    [void]$PowerShell.AddScript( {
            [CmdletBinding()]
            param (
                $Param,
                [string]$DestinationPath,
                [string[]]$SupportedProtocols,
                [string]$WorkingDirectory
            )

            ForEach-Object -InputObject $Param.InputObject {
                $Param = @{ }

                # Allow passing string[] or objects, but fail if neither.
                if ($PSItem.Server) { $Param.Add("Server", $PSItem.Server) }
                elseif (@($PSItem)[0] -is "String") { $Param.Add("Server", $PSItem) }
                else { Write-Error -ErrorAction Stop "Unable to determine argument 'server'." }

                if ($PSItem.Port) { $Param.Add("Port", $PSItem.Port) }
                if ($PSItem.Protocol) { $Param.Add("Protocol", $PSItem.Protocol) }
                $TempFileName = "$WorkingDirectory\{0} {1}.lock" -f $Param.Server, $Param.Port, $Param.Protocol
                Get-date -f s | out-file $TempFileName
                Test-TlsProtocols @Param
                sleep 1
                Remove-Item $TempFileName
            } |
            # Select-Object ("Server", "fqdn", "IP", "Port", $SupportedProtocols) |
            Export-Csv $DestinationPath -Append -NoTypeInformation

        }).AddParameters($ScriptParam)

    # Run this block until everything is done
    do {
        # Exclude previously completed scans
        if (Test-Path $DestinationPath) {
            $PreviouslyCompletedScans = Import-Csv $DestinationPath
            # Seems hard to filter by Protocol, so we'll key only on Server and Port
            $CompareParam = @{
                ReferenceObject  = $List
                DifferenceObject = $PreviouslyCompletedScans
                Property         = "Server", "Port"
                PassThru         = $true
            }
            $ScanList = (Compare-Object @CompareParam).Where{ $_.SideIndicator -eq "<=" } |
            Select -ExcludeProperty SideIndicator
        }
        else {
            $ScanList = $List
        }
        $Param.Add("InputObject", $ScanList)
        Write-Verbose "Begin scan"
        $AsyncObject = $PowerShell.BeginInvoke()

        # Mark hung scans in completed file
        do {
            $InProgressScans = Get-ChildItem "$WorkingDirectory\*.lock"
            Write-Verbose "Existing locks: $InProgressScans"
            foreach ($InProgressScan in $InProgressScans) {
                $Age = [timespan]((get-date) - $InProgressScan.LastWriteTime)
                Write-Verbose $age
                if ($Age.TotalSeconds -ge 10) {
                    Write-Verbose "Stop scan and clean up"
                    $PowerShell.Stop()
                    Remove-Variable $AsyncObject -ea silent
                    $Param.Remove("InputObject")

                    Write-Verbose "Add hung scan to DestinationPath as error"
                    $Server, $Port = $InProgressScan.BaseName -split " ", 2
                    Write-Verbose "Found hung scan: Server:$Server, Port:$Port"
                    $HungScanResults = @{
                        Server = $Server
                        Fqdn   = $null
                        IP     = $null
                        Port   = $Port
                    }
                    $SupportedProtocols | % { $HungScanResults.Add($_, "Error-Hung") }
                    [PSCustomObject]$HungScanResults | Export-Csv $DestinationPath -Append -NoType
                }
            }
            sleep 4
        } until ($AsyncObject.IsCompleted)

    } until ($AsyncObject.IsCompleted)

    $PowerShell.Dispose()


}
