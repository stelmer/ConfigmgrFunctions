
Function Set-Configmgr2107HttpsDownloadBugFix {
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$ComputerName
    )

<#
.SYNOPSIS
  Custom ConfigMgr Powershell Functions

.DESCRIPTION
  Sets IIS config on smspkg and smssig iis dirs to ignore client auth certs.

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
        Write-Output "Remediating $($ComputerName)"

    }

    process {
        
        Write-Verbose "Process $($MyInvocation.MyCommand.Name)"

        if (Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue) {  
            
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            
                [xml]$smspkg = c:\windows\system32\inetsrv\appcmd.exe list config 'Default Web Site/SMS_DP_SMSPKG$' -section:system.webServer/security/access
                Write-Output "SMS_DP_SMSPKG$ SSL Config = '$($smspkg.'system.webServer'.security.access.sslFlags)'"
                
                if ('Ssl' -eq "$($smspkg.'system.webServer'.security.access.sslFlags)") { 
                    
                    # Write-Output 'Compliant'   
                
                } Else {
                    
                    Write-Output 'Non-Compliant, remediating...'  
                    
                    Try {

                        c:\windows\system32\inetsrv\appcmd.exe set config 'Default Web Site/SMS_DP_SMSPKG$' -section:system.webServer/security/access /sslFlags:"Ssl" /commit:apphost

                    } catch {
                        
                        Write-warning 'An error occurred updating the Default Web Site/SMS_DP_SMSPKG$ SSL config'

                    }

                }

                [xml]$smssig = c:\windows\system32\inetsrv\appcmd.exe list config 'Default Web Site/SMS_DP_SMSSIG$' -section:system.webServer/security/access
                Write-Output "SMS_DP_SMSSIG$ SSL Config = '$($smssig.'system.webServer'.security.access.sslFlags)'"
                
                if ('Ssl' -eq "$($smssig.'system.webServer'.security.access.sslFlags)") { 
                
                    Write-Output "$($env:COMPUTERNAME): Compliant"   
                
                } Else {
                
                    Write-Output 'Non-Compliant, remediating...'  
                    
                    Try {

                        c:\windows\system32\inetsrv\appcmd.exe set config 'Default Web Site/SMS_DP_SMSSIG$' -section:system.webServer/security/access /sslFlags:"Ssl" /commit:apphost

                    } catch {
                        
                        Write-warning 'An error occurred updating the Default Web Site/SMS_DP_SMSSIG$ SSL config'

                    }
                
                }

            }
              
        }

    }

    End {
        
        Write-Verbose "End $($MyInvocation.MyCommand.Name)"
        
    }

}

