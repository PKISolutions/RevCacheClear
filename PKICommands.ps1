<#
 * Project: RevCacheClear
 * CRLRevocationDate setter and getter
 * (C) 2019 by PKI Solutions 
 * Author: Vadims Podans
 * Released under the GPLv3
 #>


#requires -Version 3
function Set-CRLRevocationDate {
<#
.SYNOPSIS
Sets or deletes the CRLRevocationDate registry key.

.DESCRIPTION
This Cmdlet has the same effect as the 'certutil -setreg chain\ChainCacheResyncFiletime <date>` utility
except that it can be run across the network to multiple machines on various protocols*.

Returns an object with the details of the operation(s).

.PARAMETER ComputerName
A Computer or Computer array of machines that should have their registry key set.

.PARAMETER ExpirationTime
The date we wish to set for the ChainCacheResyncFiletime registry key.

.PARAMETER Delete
Deletes the registry value.

.PARAMETER AccessMethod
Specifies the remote access method to interact with remote registry. Following access methods are
accepted:
-- NET - .NET remote registry
-- PSRemoting - PowerShell Remoting (WSMAN) protocol
-- WMI - Windows Management Instrumentation
Default is WMI protocol.

.EXAMPLE
Set-CRLRevocationDate -ComputerName workstation1 -ExpirationTime (get-date)

Will expire the cert cache right now.

.EXAMPLE
With the Active Directory cmdlets we could run:

get-adcomputer -filter "name -like '*workstation*'" | Set-CRLRevocationDate -ExpirationTime (get-date)

This will expire all computers that meet the filter (so long as they are online and available with your permissions).

.EXAMPLE
With the Active Directory cmdlets we could run:

get-adcomputer -filter "name -like '*workstation*'" | Set-CRLRevocationDate -ExpirationTime (get-date) -AccessMethod PSRemoting

This will expire all computers that meet the filter (so long as they are online and available with your permissions). Remote computers
will be accessed via PowerShell Remoting protocol.

.EXAMPLE
With the Active Directory cmdlets we could run:

get-adcomputer -filter "name -like '*workstation*'" | Set-CRLRevocationDate -Delete

This will set revocation expiration date and time to its default state.
#>

[CmdletBinding(DefaultParameterSetName = '__setValue')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]$ComputerName,
        [ValidateSet("NET", "PSRemoting", "WMI")]
        [string]$AccessMethod = "WMI",
        [Parameter(ParameterSetName = '__setValue', Mandatory = $true)]
        [DateTime]$ExpirationTime,
        [Parameter(ParameterSetName = '__delValue')]
        [switch]$Delete
    )

    begin {
        $RegKey = "SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\"
        $RegValue = "ChainCacheResyncFiletime"
        $NewValue = switch ($PSCmdlet.ParameterSetName) {
            '__setValue' {$ExpirationTime}
            '__delValue' {"null"}            
        }
        
        function __getCompName($InputObject) {
            if ($InputObject -is [Microsoft.ActiveDirectory.Management.ADComputer]) {
                $InputObject.DNSHostName
            } else {
                $InputObject
            }
        }
        function __getBinaryDateTime($date) {
            $Int64Value = $date.ToFileTime()
            [System.BitConverter]::GetBytes($Int64Value)
        }
        function __setNetAccess($comp, [Byte[]]$binDate) {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
            $key = $Reg.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config\\", $true)
            $key.SetValue($RegValue, $binDate, [Microsoft.Win32.RegistryValueKind]::Binary)
        }
        function __setPSRemotingAccess($comp, [Byte[]]$binDate) {
            Invoke-Command -ComputerName $comp -ScriptBlock {
                $prop = New-ItemProperty -Path "HKLM:\$($using:RegKey)" -Name $using:RegValue -Value $using:binDate -PropertyType Binary -Force
            } -ErrorAction Stop
        }
        function __setWmiAccess($comp, [Byte[]]$binDate) {
            $wmi = [wmiclass]"\\$comp\root\DEFAULT:StdRegProv"
            [void]$wmi.SetBinaryValue(2147483650, $RegKey, $RegValue, $binDate)
        }
        function __delNetAccess($comp) {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
            $key = $reg.OpenSubKey($RegKey.Replace("\","\\"), $true)
            if ($key.GetValueNames() -contains $RegValue) {
                $key.DeleteValue($RegValue)
            }
        }
        function __delPSRemotingAccess($comp) {
            Invoke-Command -ComputerName $comp -ScriptBlock {
                $prop = Get-ItemProperty -Path "HKLM:\$($using:RegKey)" -Name $using:RegValue -ErrorAction SilentlyContinue
                if ($prop -eq $null) {
                    return
                }
                [void](Remove-ItemProperty -Path "HKLM:\$($using:RegKey)" -Name $using:RegValue)
            } -ErrorAction Stop
        }
        function __delWmiAccess($comp) {
            $wmi = [wmiclass]"\\$comp\root\DEFAULT:StdRegProv"
            [void]$wmi.DeleteValue(2147483650, $RegKey, $RegValue)
        }
    }

    process {
        $ComputerName | ForEach-Object {
            $comp = __getCompName $_
            $obj = New-Object psobject -Property @{
                Status            = "N/A"
                CRLRevocationDate = $NewValue
                AccessMethod      = $AccessMethod
                Computer          = $comp
                Exception         = $null
            }
            try  {
                switch ($PSCmdlet.ParameterSetName) {
                    '__setValue' {
                        $binDate = __getBinaryDateTime $ExpirationTime
                        switch ($AccessMethod) {
                            "NET" {__setNetAccess $comp $binDate}
                            "PSRemoting" {__setPSRemotingAccess $comp $binDate}
                            "WMI" {__setWmiAccess $comp $binDate}
                        }
                    }
                    '__delValue' {
                        switch ($AccessMethod) {
                            "NET" {__delNetAccess $comp}
                            "PSRemoting" {__delPSRemotingAccess $comp}
                            "WMI" {__delWmiAccess $comp}
                        }
                    }
                }
                $obj.Status = "Complete"
            } catch {
                throw $_
                $obj.Exception = $_.Exception.GetType().FullName
                $obj.Status = "Failed"
            }
            $obj
        }
    }
}

function Get-CRLRevocationDate  {
<#
.SYNOPSIS
Gets the CRLRevocationDate registry key.

.DESCRIPTION
This Cmdlet has the same effect as the 'certutil -getreg chain\ChainCacheResyncFiletime` command
except that it can be run across the network to multiple machines on various protocols*.

Returns an object with the details of the operation(s).

Note: The command cannot be run against localhost.

.PARAMETER ComputerName
A Computer or Computer array of machines that should have their registry key set.
Accepts Pipeline input.

.PARAMETER AccessMethod
Specifies the remote access method to interact with remote registry. Following access methods are
accepted:
-- NET - .NET remote registry
-- PSRemoting - PowerShell Remoting (WSMAN) protocol
-- WMI - Windows Management Instrumentation
Default is WMI protocol

.EXAMPLE
Get-CRLRevocationDate -ComputerName workstation1

Status   CRLRevocationDate    ObtainedFrom    Computer      Exception
------   -----------------    ------------    --------      ---------
Complete 6/2/2018 12:56:08 PM Remote Registry workstation1


.EXAMPLE
With the Active Directory cmdlets we could run:

get-adcomputer -filter "samaccountname -like 'workstation1*'" | Get-CRLRevocationDate 

Status   CRLRevocationDate    ObtainedFrom    Computer      Exception
------   -----------------    ------------    --------      ---------
Complete 6/2/2018 12:56:08 PM Remote Registry workstation1

This will expire all computers that meet the filter (so long as they are online and available with your permissions).
#>
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]$ComputerName,
        [ValidateSet("NET", "PSRemoting", "WMI")]
        [string]$AccessMethod = "WMI"
    )
    
    begin {
        $RegKey = "SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\"
        $RegValue = "ChainCacheResyncFiletime"
        $NotSet = "Not set"
        
        function __getCompName($InputObject) {
            if ($InputObject -is [Microsoft.ActiveDirectory.Management.ADComputer]) {
                $InputObject.DNSHostName
            } else {
                $InputObject
            }
        }
        function __getBinaryDateTime([Byte[]]$bytes) {
            if (!$bytes) {
                $false
                return
            }
            $Int64Value = [System.BitConverter]::ToInt64($bytes, 0)
            [DateTime]::FromFileTime($Int64Value)
        }
        # returns:
        # false -- reg value not found
        # other -- date/time
        function __getNetAccess($comp) {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
            $key = $reg.OpenSubKey($RegKey.Replace("\","\\"))
            if ($key.GetValueNames() -notcontains $RegValue) {
                $false
                return
            }
            $bytes = $key.GetValue($RegValue)
            __getBinaryDateTime $bytes
        }
        # returns date/time object
        function __getPSRemotingAccess($comp) {
            $value = Invoke-Command -ComputerName $comp -ScriptBlock {
                $prop = Get-ItemProperty -Path "HKLM:\$($using:RegKey)" -Name $using:RegValue -ErrorAction SilentlyContinue
                if ($prop -eq $null) {
                    $false
                    return
                }
                $prop."$using:RegValue"
            } -ErrorAction Stop
            __getBinaryDateTime $value
        }
        # returns date/time object
        function __getWmiAccess($comp) {
            $wmi = [wmiclass]"\\$comp\root\DEFAULT:StdRegProv"
            $prop = $wmi.GetBinaryValue(2147483650,$RegKey,$RegValue)
            if ($prop -eq $null) {
                $false
                return
            }
            __getBinaryDateTime $prop.uValue
        }
    }

    process {
        $ComputerName | ForEach-Object {
            $comp = __getCompName $_
            $obj = New-Object psobject -Property @{
                Status            = "N/A"
                CRLRevocationDate = "N/A"
                AccessMethod      = $AccessMethod
                Computer          = $comp
                Exception         = $null
            }
            # trying to use remote registry... safest bet since winrm isn't on by default.
            try  {
                $value = switch ($AccessMethod) {
                    "NET"        {__getNetAccess $comp}
                    "PSRemoting" {__getPSRemotingAccess $comp}
                    "WMI"        {__getWmiAccess $comp}
                }
                $obj.CRLRevocationDate = if ($value -is [DateTime]) {$value} else {$NotSet}
                $obj.Status = "Complete"
            } catch {
                $obj.Exception = $_.Exception.GetType().FullName
                $obj.Status = "Failed"
            }
            $obj
        }
    }
}
