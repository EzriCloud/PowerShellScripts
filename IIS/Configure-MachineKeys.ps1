[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string[]] $ComputerName = $env:COMPUTERNAME,

    [ValidateSet('Read', 'Write')]
    [Alias('ReadWrite')]
    [string] $Mode = 'Read',

    [string[]] $ValidationKey,
    [string[]] $DecryptionKey,
    [string[]] $ValidationMode = "SHA1"
)


$global:netfxFolders = @{ 
    'Framework 1.1 x86' = 'C:\WINDOWS\Microsoft.NET\Framework\v1.1.4322\CONFIG';
    'Framework 2.0 x86' = 'C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\CONFIG'; 
    'Framework 4.0 x86' = 'C:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\CONFIG'; 
    'Framework 2.0 x64' = 'C:\WINDOWS\Microsoft.NET\Framework64\v2.0.50727\CONFIG'; 
    'Framework 4.0 x64' = 'C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\CONFIG';
}


function Generate-Key {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Validationkey', 'DecryptionKey')]
        [string] $Key
    )
    switch ($Key) {
        'Validationkey' { $KeyLength = 64 }
        'DecryptionKey' { $KeyLength = 24 }
    }
    
    $Buffer = New-Object 'System.Byte[]' $KeyLength
    $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $RNG.GetBytes($Buffer)
    (0..$KeyLength | ForEach-Object {'{0:X2}' -f $Buffer[$_] }) -join ''

    <#
    .Synopsis
    Generates a Validationkey or DecryptionKey using random cryptographically bytes

    .Description
    Uses RNGCryptoServiceProvider to generate arrays of random bytes

    .Links
    http://msdn.microsoft.com/en-us/library/w8h3skw9(v=vs.100).aspx

    .Parameter Key
    The Key type selected, controls the length of the key to generate
    #>
}


function New-Keys {
    $validationkey = Generate-Key -Key Validationkey
    $decryptionKey = Generate-Key -Key DecryptionKey
    $validation = 'SHA1'
    New-Object -TypeName PSObject -Property @{
        Validationkey = $validationkey
        DecryptionKey = $decryptionKey
        Validation = $validation
    }

    <#
    .Synopsis
    Generates a set of SHA mode Validationkey & DecryptionKey

    .Description
    Requires the Generate-Key function
    #>
}


function Get-Keys {
    [cmdletbinding()]
    param(
        [string] $ComputerName = $env:COMPUTERNAME
    )

    if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
        $global:netfxFolders.GetEnumerator() | Sort-Object Name | ForEach-Object { 

            $NetFxVersion = $_.Name
            $MachineConfig = $_.Value + '\machine.config'
            $MachineConfig = $MachineConfig -replace [regex]::Escape('C:\WINDOWS\'), "\\$ComputerName\Admin`$\"

            if (Test-Path -Path $MachineConfig -PathType Leaf) {
                [xml] $xmlMachineConfig = [xml] (Get-Content -Path $MachineConfig)
                $SystemWeb = $xmlMachineConfig.get_DocumentElement().'system.web'
                if ($SystemWeb.machineKey) {
                    New-Object -TypeName PSObject -Property @{ 
                        ComputerName = $ComputerName
                        NetFxVersion = $NetFxVersion
                        ValidationKey = $SystemWeb.SelectSingleNode('machineKey').GetAttribute('validationKey')
                        DecryptionKey = $SystemWeb.SelectSingleNode('machineKey').GetAttribute('decryptionKey')
                        Validation = $SystemWeb.SelectSingleNode('machineKey').GetAttribute('validation')
                    } | Select-Object ComputerName, NetFxVersion, ValidationKey, DecryptionKey, Validation
                } else {
                    Write-Verbose "$NetFxVersion doesn't have a machineKey node on $ComputerName"
                }

            } else {
                Write-Verbose "$NetFxVersion is not installed on $ComputerName"
            }
        }
    } else { 
        Write-Warning "$ComputerName is unreachable" 
    }

    <#
    .Synopsis
    Gets the validation mode, Validationkey and DecryptionKey of each of the .NET CLRs installed

    .Description
    Requires the Generate-Key function

    .Parameter ComputerName
    The netbios name, FQDN or IP Address of the remote computer to retreive the information from
    #>
}


function Set-Keys {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string] $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$true)]
        [PSObject] $Keys
    )

    if($PSCmdlet.ShouldProcess($ComputerName, "Configure the machineKeys in the machine.config files")) {

        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
            $global:netfxFolders.GetEnumerator() | Sort-Object Name | ForEach-Object { 
    
                $NetFxVersion = $_.Name
                $MachineConfig = $_.Value + '\machine.config'
                $MachineConfig = $MachineConfig -replace [regex]::Escape('C:\WINDOWS\'), "\\$ComputerName\Admin`$\"

                if (Test-Path -Path $MachineConfig -PathType Leaf) {

                    Copy-Item -Path $MachineConfig -Destination ($MachineConfig -replace '\.config', ('_{0:yyyyMMddHHmm}.config' -f (Get-Date))) -Force

                    [xml] $xmlMachineConfig = [xml] (Get-Content -Path $MachineConfig)
                    $SystemWeb = $xmlMachineConfig.get_DocumentElement().'system.web'
            
                    if ($SystemWeb.machineKey -eq $null) { 
                        $machineKey = $xmlMachineConfig.CreateElement('machineKey')
                        [void]$SystemWeb.AppendChild($machineKey)
                    }

                    $SystemWeb.SelectSingleNode('machineKey').SetAttribute('validationKey', $Keys.Validationkey)
                    $SystemWeb.SelectSingleNode('machineKey').SetAttribute('decryptionKey', $Keys.DecryptionKey)
                    $SystemWeb.SelectSingleNode('machineKey').SetAttribute('validation', $Keys.Validation)
                    $xmlMachineConfig.Save($MachineConfig)

                    if ($?) {
                        New-Object -TypeName PSObject -Property @{ 
                            ComputerName = $ComputerName
                            NetFxVersion = $NetFxVersion
                            ValidationKey = $Keys.Validationkey
                            DecryptionKey = $Keys.DecryptionKey
                            Validation = $Keys.Validation
                        } | Select-Object ComputerName, NetFxVersion, ValidationKey, DecryptionKey, Validation
                    }

                } else {
                    Write-Verbose "$NetFxVersion is not installed on $ComputerName"
                }
            }
        } else {
            Write-Warning "$ComputerName is unreachable"
        }
    }
    <#
    .Synopsis
    Sets the provided validation mode, Validationkey and DecryptionKey of each of the .NET CLRs installed

    .Description
    Requires the Generate-Key function

    .Parameter ComputerName
    The netbios name, FQDN or IP Address of the remote computer to retreive the information from

    .Parameter Keys
    A psobject (generated by the New-Keys function) containing the validation mode, Validationkey and DecryptionKey
    #>
}


Write-Verbose "Running in $Mode mode" -Verbose
switch ($Mode) {
    'Read' {
        $ComputerName | ForEach-Object {
            Get-Keys -ComputerName $_
        }
    }

    'Write' {
        if (!$ValidationKey) {
            Write-Verbose "Generating new keys"
            $Keys = New-Keys
        } else {
            Write-Verbose "Using keys you provided"
            $Keys = New-Object -TypeName PSObject -Property @{
                Validationkey = $ValidationKey
                DecryptionKey = $DecryptionKey
                Validation = $ValidationMode
            }
        }
        $ComputerName | ForEach-Object {
            Set-Keys -Keys $Keys -ComputerName $_
        }
    }
    
}