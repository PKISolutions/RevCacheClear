<#
 * Project: RevCacheClear
 * CRLRevocationDate setter and getter
 * (C) 2018 by PKI Solutions 
 * Author: (gsamuelhays@gmail.com)
 * Released under the GPLv3
 #>


#requires -Version 3
Import-Module .\HelperFunctions.psm1
function Set-CRLRevocationDate {
<#
    .SYNOPSIS 
    Sets the CRLRevocationDate registry key.

    .DESCRIPTION 
    This Cmdlet has the same effect as the 'certutil -setreg chain\ChainCacheResyncFiletime <date>` utility
    except that it can be run across the network to multiple machines on various protocols*.

    Returns an object with the details of the operation(s).

    Note: The command cannot be run against localhost.

    .PARAMETER ComputerName
    A Computer or Computer array of machines that should have their registry key set.

    .PARAMETER ExpirationTime
    The date we wish to set for the ChainCacheResyncFiletime registry key.

    .EXAMPLE
    Set-CRLRevocationDate -ComputerName workstation1 -ExpirationTime (get-date)

    Will expire the cert cache right now.

    .EXAMPLE
    With the Active Directory cmdlets we could run:

    get-adcomputer -filter "name -like '*workstation*'" | Set-CRLRevocationDate -ExpirationTime (get-date)

    This will expire all computers that meet the filter (so long as they are online and available with your permissions).
#>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
        )]
        [string[]]
        $ComputerName,

        [Parameter(
            Mandatory=$true
        )]
        [DateTime]
        $ExpirationTime
    )

    Begin {
        $bytes = Convert-DatetimeToRegistryDate $ExpirationTime
    }

    Process {
        $ComputerName | ForEach-Object {
            $comp = $_
            $obj = New-Object psobject
            $obj | Add-Member -MemberType NoteProperty -Name Status -Value "N/A"
            $obj | Add-Member -MemberType NoteProperty -Name CRLRevocationDate -Value $ExpirationTime
            $obj | Add-Member -MemberType NoteProperty -Name SetWith -Value "N/A"
            $obj | Add-Member -MemberType NoteProperty -Name Computer -Value $comp
            $obj | Add-Member -MemberType NoteProperty -Name Exception -Value "N/A"
            try  {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $Reg.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config\\", $true)
                $key.SetValue("ChainCacheResyncFiletime", [byte[]]$bytes, [Microsoft.Win32.RegistryValueKind]::Binary)
                $obj.SetWith = "Remote Registry"
                $obj.Status = "Set"
            } catch [Exception] {
                $obj.Exception = $_.Exception.GetType().FullName
                $obj.Status = "Failed"
            }
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
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
        )]
        [string[]]
        $ComputerName
    )

    Process {
        $ComputerName | ForEach-Object {
            $comp = $_
            $obj = New-Object psobject
            $obj | Add-Member -MemberType NoteProperty -Name Status -Value "N/A"
            $obj | Add-Member -MemberType NoteProperty -Name CRLRevocationDate -Value "N/A"
            $obj | Add-Member -MemberType NoteProperty -Name ObtainedFrom -Value "N/A"
            $obj | Add-Member -MemberType NoteProperty -Name Computer -Value $comp
            $obj | Add-Member -MemberType NoteProperty -Name Exception -Value $null
            # trying to use remote registry... safest bet since winrm isn't on by default.
            try  {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $comp)
                $key = $Reg.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config\\")
                $bytes = $key.GetValue("ChainCacheResyncFiletime")
                $dt = Convert-RegistryDateToDatetime -regDateBytes $bytes
                $obj.CRLRevocationDate = if ($dt -eq $False) { "Not Set" } else { $dt }
                $obj.Status = "Complete"
                $obj.ObtainedFrom = "Remote Registry"
               
            } catch [System.Security.SecurityException] {
                # this can happen if you're trying to read the local registry
                $obj.Exception = $_.Exception.GetType().FullName
                $obj.Status = "Failed"
            } catch [System.IO.IOException] {
                # this can happen if the box isn't available on the network
                $obj.Exception = $_.Exception.GetType().FullName
                $obj.Status = "Failed"
            }
            $obj
        }
    }
}

