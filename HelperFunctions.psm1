<#
 * Project: RevCacheClear
 * Registry Datetime helper functions
 * (C) 2018 by PKI Solutions 
 * Author: (gsamuelhays@gmail.com)
 * Released under the GPLv3
 #>
function Convert-RegistryDateToDatetime([byte[]]$regDateBytes) {
<#
    .SYNOPSIS 
    Converts REG_BINARY dates to a DateTime object.

    .DESCRIPTION 
    Some tools and services store DateTime objects in a binary format in the
    registry. This function converts those back to a datetime object.

    Returns DateTime if one is found, False if unable to convert.

    .PARAMETER bytes
    The byte array (byte[]) read in from the registry.

    .EXAMPLE
    Read a binary date from the registry and convert.

    $reg = 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\'
    [byte[]]$bytes = (get-itemproperty $reg).ChainCacheResyncFiletime
    Convert-RegistryDateToDatetime -b $bytes

    Saturday, May 26, 2018 7:38:29 PM

    .LINK
    http://sams.site/blog/2018/05/13/Dealing-with-Reg_Binary-Dates-in-Powershell.html

#>

    if ($null -eq $regDateBytes -or $regDateBytes.Count -lt 8) {
        return $False
    }

    try  {
        # take our date and convert to a datetime format.
        [long]$f = ([long]$regDateBytes[7] -shl 56) `
                    -bor ([long]$regDateBytes[6] -shl 48) `
                    -bor ([long]$regDateBytes[5] -shl 40) `
                    -bor ([long]$regDateBytes[4] -shl 32) `
                    -bor ([long]$regDateBytes[3] -shl 24) `
                    -bor ([long]$regDateBytes[2] -shl 16) `
                    -bor ([long]$regDateBytes[1] -shl 8) `
                    -bor [long]$regDateBytes[0]

        return [datetime]::FromFileTime($f)
    } catch [Exception] {
        return $False
    }
}

function Convert-DatetimeToRegistryDate($datetime) {
    <#
        .SYNOPSIS
        Converts a DateTime object to a REG_BINARY array suitable for some needs.

        .DESCRIPTION
        If you need to store a DateTime in the REG_BINARY format used by some tools and services, this
        function will convert the DateTime to the byte array.

        .PARAMETER dt
        A DateTime object to convert to the binary format.

        .EXAMPLE
        $reg = 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\'

        $bytes = Convert-DatetimeToRegistryDate (get-date)

        New-ItemProperty -Path $reg -Name ChainCacheResyncFiletime -PropertyType Binary -Value $bytes

        .LINK
        http://sams.site/blog/2018/05/13/Dealing-with-Reg_Binary-Dates-in-Powershell.html
    #>
    [long]$ft = $datetime.toFileTime()
    $arr = @()
    0..7 | ForEach-Object {
        $arr += ([byte](($ft -shr (8 * $_)) -band 0xFF))
    }
    return [byte[]]$arr
}
