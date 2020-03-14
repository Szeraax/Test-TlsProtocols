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
    Array of objects for the list of servers, ports, and protocol names (space delimited) to test. Can be piped from an Import-Csv cmdlet.
    Expects the following case-insensitive property names: Host, Port, Protocol

.PARAMETER Taskers
    Computers to distribute the load between. Defaults to localhost only.

.PARAMETER DisableParallel
    Defaults to use foreach -Parallel in pwsh7 if available. Use this switch to not do use that capability

.PARAMETER DestinationPath
    If specified, output to path instead of Write-Output.
    If specified, any results in DestinationPath and all 'frozen' scans located in $WorkingDirectory will be skipped that come through input. Force running on all inputs via -Force

.PARAMETER Force
    Switch to force testing all input rows and overwrite existing DestinationPath.

.PARAMETER WorkingDirectory
    Where to store temporary working files. Defaults to $PSScriptDir.
#>

[CmdletBinding(
    SupportsShouldProcess
)]
param (
    [Parameter(
        Mandatory,
        ValueFromPipeline
    )]
    $InputObject
)

begin {
    $SupportedProtocolNames = ([System.Security.Authentication.SslProtocols]).GetEnumValues().Where{ $_ -ne 'Default' -and $_ -ne 'None' }
    Write-Verbose "Supported tls protocols:"
    $SupportedProtocolNames | ForEach-Object { Write-Verbose "$_" }


}

process {

}

end {

}
