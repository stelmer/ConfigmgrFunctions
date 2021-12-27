
Function Get-Configmgr2107HttpsDownloadBugFix {
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$ComputerName
    )

<#
.SYNOPSIS
  Custom ConfigMgr Powershell Functions

.DESCRIPTION
  Gets the SSL IIS config on smspkg and smssig iis dirs.

.PARAMETER ComputerName
    The computer name of the device to check.

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Version:        1.0
  Author:         Steve Jesok
  Creation Date:  12/27/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
  Set-Config2107HttpsDownloadBugFix -ComputerName [ComputerName]
#>

    begin {
        
        Write-Verbose "Begin $($MyInvocation.MyCommand.Name)"

    }

    process {
        
        Write-Verbose "Process $($MyInvocation.MyCommand.Name)"

        if (Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue) {  
            
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            
                [xml]$smspkg = c:\windows\system32\inetsrv\appcmd.exe list config 'Default Web Site/SMS_DP_SMSPKG$' -section:system.webServer/security/access
                Write-Verbose "SMS_DP_SMSPKG$ SSL Config = '$($smspkg.'system.webServer'.security.access.sslFlags)'"
                
                if ('Ssl' -eq "$($smspkg.'system.webServer'.security.access.sslFlags)") { 
                
                    Write-Output 'Compliant'   
                
                } Else {
                
                    Write-Output "$($env:COMPUTERNAME): Non-Compliant"  
                
                }

            }
              
        }

    }

    End {
        
        Write-Verbose "End $($MyInvocation.MyCommand.Name)"
        
    }

}

