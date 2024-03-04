# vCenter Server to deploy Aria Suite
$vCenterServerFQDN = "FILL_ME_IN"
$vCenterUsername = "FILL_ME_IN"
$vCenterPassword = "FILL_ME_IN"

$VMDatacenter = "Primp-Datacenter"
$VMFolder = "Workloads"
$VMCluster = "Supermicro-Cluster"
$VMResourePool = "Workload"
$VMNetwork = "VM Network"
$VMDatastore = "sm-vsanDatastore"
$VMNetmask = "255.255.255.0"
$VMGateway = "192.168.30.1"
$VMDNS = "192.168.30.2"
$VMNTP = "pool.ntp.org"
$VMDomain = "primp-industries.local"

# Aria Suite Lifecycle Manager Configurations
$AriaSuiteLifecycleVMName = "aria-lifecycle"
$AriaSuiteLifecycleHostname = "aria-lcm"
$AriaSuiteLifecycleIP = "192.168.30.91"
$AriaSuiteLifecycleRootPassword = "VMware1!"
$AriaSuiteLifecycleAdminPassword = "VMware1!"
$AriaSuiteLifecycleOVA = "/Volumes/Storage/Software/VMware-Aria-Suite-Lifecycle-Installer-22630473/vrlcm/VMware-Aria-Suite-Lifecycle-Appliance-8.14.0.4-22630472.ova"

# Aria Product Repo Configurations
$diskExpansionInGB = 20
$AriaProductRepoPath = "/data/repo"
$AriaIdentityOVAFilename = "" # Add identity-manager-3.3.7.0-21173100_OVF10.ova to deploy
$AriaOperationsOVAFilename = "" # Add vRealize-Operations-Manager-Appliance-8.14.0.22610776.ova to deploy
$AriaLogsOVAFilename = "" # Add VMware-vRealize-Log-Insight-8.14.0.0-22564181.ova to deploy
$AriaAutomationOVAFilename = "" # Add Prelude_VA-8.14.0.33079-22618990_OVF10.ova to deploy

# Aria Product License Configuations
$AriaOperationsLicenseKey = ""
$AriaOperationsLicenseAlias = "Aria Operations License"
$AriaLogsLicenseKey = ""
$AriaLogsLicenseAlias = "Aria Logs License"
$AriaAutomationLicenseKey = ""
$AriaAutomationLicenseAlias = "Aria Automation License"

# Aria Product Credential Configurations
$vCenterCredentialAlias = "vCenter Server Credentials"
$AriaProductCredentialAlias = "Aria Default Credentials"
$AriaProductDefaultUserName = "admin"
$AriaProductDefaultPassword = "VMware1!"

# Aria Env Configurations
$AriaDatacenterName = "Primp-Industries"
$AriaDatacenterLocation = "Palo Alto;California;US;37.44188;-122.14302"

# Aria Product Certificate Configurations
$AriaProductCertificateAlias = "Aria Certificates"
$AriaProductCertificateCN = "*.primp-industries.local"
$AriaProductCertificateOrganization = "Primp-Industries"
$AriaProductCertificateOU = "R&D"
$AriaProductCertificateCountry = "US"
$AriaProductCertificateLocale = "Palo Alto"
$AriaProductCertificateState = "California"
$AriaProductCertificateKeyLength = 2048
$AriaProductCertificateKeyValidity = 2048
$AriaProductCertificateDomain = @("*.primp-industries.local")
$AriaProductCertificateIP = @("192.168.30.92","192.168.30.93","192.168.30.94","192.168.30.95")

# Aria Identity Configurations
$AriaIdentityVMName = "aria-identity"
$AriaIdentityHostname = "aria-idt"
$AriaIdentityIP = "192.168.30.92"
$AriaIdentityNodeSize = "small"
$AriaIdentityConfigUsername = "primp-admin"
$AriaIdentityConfigEmail = "primp-admin@primp-industries.local"

# Aria Operations Configurations
$AriaOperationsVMName = "aria-operations"
$AriaOperationsHostname = "aria-ops"
$AriaOperationsIP = "192.168.30.93"
$AriaOperationsNodeSize = "xsmall" # xsmall, small, medium, large or xlarge
$AriaOperationsDisableTLS = "TLSv1" # TLSv1, TLSv1.1 or TLSv1,TLSv1.1

# Aria Logs Configurations
$AriaLogsVMName = "aria-logs"
$AriaLogsHostname = "aria-logs"
$AriaLogsIP = "192.168.30.94"
$AriaLogsNodeSize = "small" # small or medium

# Aria Automation Configurations
$AriaAutomationVMName = "aria-automation"
$AriaAutomationHostname = "aria-atm"
$AriaAutomationIP = "192.168.30.95"
$AriaAutomationNodeSize = "medium" # medium or xlarge

# Enable Debugging
$debug = $true

#### DO NO EDIT BEYOND HERE ####

$verboseLogFile = "aria-suite-deployment.log"
$AriaSuiteLifecycleFQDN = "${AriaSuiteLifecycleHostname}.${VMDomain}"
$global:ariaSuiteLifecycleHeaders = $null

if($PSVersionTable.PSEdition -ne "Core") {
    Write-Error "PowerShell Core is required to use this script"
    break
}

$confirmDeployment = 1
$deployAriaLCM = 1
$verifyAriaOVAUPload = 1
$changeAdminPassword = 1
$confirmNewAriaCreds = 1
$configAriaProductRepo = 1
$configAriaProductDownloadBinary = 1
$configAriaProductNTP = 1
$configAriaProductDNS = 1
$configAriaProductCredentials = 1
$configvCenterCredentials = 1
$configAriaDiskExpansion = 1
$configAriaLicenses = 1
$configAriaDatacenter = 1
$configAriavCenter = 1
$configAriavCertificates = 1
$configAriaIdentityEnv = 1
$configAriaProductEnv = 1

Function My-Logger {
    param(
    [Parameter(Mandatory=$true)][String]$message,
    [Parameter(Mandatory=$false)][String]$color="green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor $color " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

if($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- Automated Aria Suite Lifecycle Manager Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "VM Name: "
    Write-Host -ForegroundColor White $AriaSuiteLifecycleVMName
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -NoNewline -ForegroundColor White $AriaSuiteLifecycleHostname
    Write-Host -NoNewline -ForegroundColor Green " IP Address: "
    Write-Host -ForegroundColor White $AriaSuiteLifecycleIP
    Write-Host -NoNewline -ForegroundColor Green "Aria Datacenter: "
    Write-Host -ForegroundColor White $AriaDatacenterName
    Write-Host -NoNewline -ForegroundColor Green "Aria Location: "
    Write-Host -ForegroundColor White $AriaDatacenterLocation
    Write-Host -NoNewline -ForegroundColor Green "Product Repo Disk Expansion (GB): "
    Write-Host -ForegroundColor White $diskExpansionInGB
    Write-Host -NoNewline -ForegroundColor Green "Product Repo Path: "
    Write-Host -ForegroundColor White $AriaProductRepoPath
    Write-Host -NoNewline -ForegroundColor Green "OVA: "
    Write-Host -ForegroundColor White $( ($AriaSuiteLifecycleOVA -split "/")[-1])
    Write-Host -ForegroundColor Green "`nAria Certificate Configurations: "
    Write-Host -NoNewline -ForegroundColor Green "Key Length: "
    Write-Host -NoNewline -ForegroundColor White $AriaProductCertificateKeyLength
    Write-Host -NoNewline -ForegroundColor Green " Key Validity: "
    Write-Host -ForegroundColor White $AriaProductCertificateKeyValidity
    Write-Host -NoNewline -ForegroundColor Green "Organization: "
    Write-Host -NoNewline -ForegroundColor White $AriaProductCertificateOrganization
    Write-Host -NoNewline -ForegroundColor Green " Organization Unit: "
    Write-Host -ForegroundColor White $AriaProductCertificateOU
    Write-Host -NoNewline -ForegroundColor Green "Country: "
    Write-Host -NoNewline -ForegroundColor White $AriaProductCertificateCountry
    Write-Host -NoNewline -ForegroundColor Green "` State: "
    Write-Host -NoNewline -ForegroundColor White $AriaProductCertificateState
    Write-Host -NoNewline -ForegroundColor Green " Locale: "
    Write-Host -ForegroundColor White $AriaProductCertificateLocale
    Write-Host -NoNewline -ForegroundColor Green "Common Name: "
    Write-Host -NoNewline -ForegroundColor White $AriaProductCertificateCN
    Write-Host -NoNewline -ForegroundColor Green "` Domains: "
    Write-Host -ForegroundColor White $AriaProductCertificateDomain
    Write-Host -NoNewline -ForegroundColor Green "IPs: "
    Write-Host -ForegroundColor White $AriaProductCertificateIP

    if($AriaIdentityOVAFilename -ne "") {
        Write-Host -ForegroundColor Yellow "`n---- Aria Identity Manager Configuration ---- "
        Write-Host -NoNewline -ForegroundColor Green "VM Name: "
        Write-Host -NoNewline -ForegroundColor White $AriaIdentityVMName
        Write-Host -NoNewline -ForegroundColor Green " Node Size: "
        Write-Host -ForegroundColor White $AriaIdentityNodeSize
        Write-Host -NoNewline -ForegroundColor Green "Hostname: "
        Write-Host -NoNewline -ForegroundColor White $AriaIdentityHostname
        Write-Host -NoNewline -ForegroundColor Green " IP Address: "
        Write-Host -ForegroundColor White $AriaIdentityIP
        Write-Host -NoNewline -ForegroundColor Green "Config Username: "
        Write-Host -ForegroundColor White $AriaIdentityConfigUsername
        Write-Host -NoNewline -ForegroundColor Green "OVA: "
        Write-Host -ForegroundColor White $AriaIdentityOVAFilename
    }

    if($AriaOperationsOVAFilename -ne "" -and $AriaOperationsLicenseKey -ne "") {
        Write-Host -ForegroundColor Yellow "`n---- Aria Operations Configuration ---- "
        Write-Host -NoNewline -ForegroundColor Green "VM Name: "
        Write-Host -NoNewline -ForegroundColor White $AriaOperationsVMName
        Write-Host -NoNewline -ForegroundColor Green " Node Size: "
        Write-Host -ForegroundColor White $AriaOperationsNodeSize
        Write-Host -NoNewline -ForegroundColor Green "Hostname: "
        Write-Host -NoNewline -ForegroundColor White $AriaOperationsHostname
        Write-Host -NoNewline -ForegroundColor Green " IP Address: "
        Write-Host -ForegroundColor White $AriaOperationsIP
        Write-Host -NoNewline -ForegroundColor Green "Disabled TLS: "
        Write-Host -ForegroundColor White $AriaOperationsDisableTLS
        Write-Host -NoNewline -ForegroundColor Green "OVA: "
        Write-Host -ForegroundColor White $AriaOperationsOVAFilename
    }

    if($AriaLogsOVAFilename -ne "" -and $AriaLogsLicenseKey -ne "") {
        Write-Host -ForegroundColor Yellow "`n---- Aria Operations for Logs Configuration ---- "
        Write-Host -NoNewline -ForegroundColor Green "VM Name: "
        Write-Host -NoNewline ForegroundColor White $AriaLogsVMName
        Write-Host -NoNewline -ForegroundColor Green " Node Size: "
        Write-Host -ForegroundColor White $AriaLogsNodeSize
        Write-Host -NoNewline -ForegroundColor Green "Hostname: "
        Write-Host -NoNewline -ForegroundColor White $AriaLogsHostname
        Write-Host -NoNewline -ForegroundColor Green " IP Address: "
        Write-Host -ForegroundColor White $AriaLogsIP
        Write-Host -NoNewline -ForegroundColor Green "OVA: "
        Write-Host -ForegroundColor White $AriaLogsOVAFilename
    }

    if($AriaAutomationOVAFilename -ne "" -and $AriaAutomationLicenseKey -ne "") {
        Write-Host -ForegroundColor Yellow "`n---- Aria Automation Configuration ---- "
        Write-Host -NoNewline -ForegroundColor Green "VM Name: "
        Write-Host -NoNewline -ForegroundColor White $AriaAutomationVMName
        Write-Host -NoNewline -ForegroundColor Green " Node Size: "
        Write-Host -ForegroundColor White $AriaAutomationNodeSize
        Write-Host -NoNewline -ForegroundColor Green "Hostname: "
        Write-Host -NoNewline -ForegroundColor White $AriaAutomationHostname
        Write-Host -NoNewline -ForegroundColor Green " IP Address: "
        Write-Host -ForegroundColor White $AriaAutomationIP
        Write-Host -NoNewline -ForegroundColor Green "OVA: "
        Write-Host -ForegroundColor White $AriaAutomationOVAFilename
    }

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
    Clear-Host
}

if($deployAriaLCM -eq 1) {
    My-Logger "Logging into management vCenter Server ..."
    Connect-VIServer -Server $vCenterServerFQDN -User $vCenterUsername -Password $vCenterPassword | Out-Null

    if(Get-View -ViewType VirtualMachine -Property Name -Filter @{"name"=$AriaSuiteLifecycleVMName}) {
        $ovfconfig = Get-OvfConfiguration $AriaSuiteLifecycleOVA

        # New OVF property in Aria LCM 8.16
        if($ovfconfig.Common.admin_password) {
            $changeAdminPassword = 0
        }

        My-Logger "Aria Suite Lifecycle Manager has already been deployed ..."
        Disconnect-VIServer * -Confirm:$false | Out-Null
    } else {
        $ovfconfig = Get-OvfConfiguration $AriaSuiteLifecycleOVA

        $networkMapLabel = ($ovfconfig.ToHashTable().keys | where {$_ -Match "NetworkMapping"}).replace("NetworkMapping.","").replace("-","_").replace(" ","_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $VMNetwork
        $ovfconfig.common.vami.hostname.value = $AriaSuiteLifecycleFQDN
        $ovfconfig.vami.VMware_Aria_Suite_Lifecycle_Appliance.ip0.value = $AriaSuiteLifecycleIP
        $ovfconfig.vami.VMware_Aria_Suite_Lifecycle_Appliance.netmask0.value = $VMNetmask
        $ovfconfig.vami.VMware_Aria_Suite_Lifecycle_Appliance.gateway.value = $VMGateway
        $ovfconfig.vami.VMware_Aria_Suite_Lifecycle_Appliance.DNS.value = $VMDNS
        $ovfconfig.vami.VMware_Aria_Suite_Lifecycle_Appliance.searchpath.value = $VMDomain

        $ovfconfig.common.varoot_password.value = $AriaSuiteLifecycleRootPassword
        $ovfconfig.common.va_ssh_enabled.value = "True"
        $ovfconfig.common.va_firstboot_enabled.value = "True"
        $ovfconfig.common.va_telemetry_enabled.value = "False"
        $ovfconfig.common.va_fips_enabled.value = "False"
        $ovfconfig.common.va_ntp_servers.value = $VMNTP

        # New OVF property in Aria LCM 8.16
        if($ovfconfig.Common.admin_password) {
            $ovfconfig.Common.admin_password.Value = $AriaSuiteLifecycleAdminPassword
            $changeAdminPassword = 0
        }

        $datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select -First 1
        $cluster = Get-Cluster -Server $viConnection -Name $VMCluster
        $vmhost = $cluster | Get-VMHost | Get-Random -Count 1
        $vmfolder = Get-Folder -Name $VMFolder

        My-Logger "Deploying Aria Suite Lifecycle Manager VM $AriaSuiteLifecycleVMName ..."
        $vm = Import-VApp -Source $AriaSuiteLifecycleOVA  -OvfConfiguration $ovfconfig -Name $AriaSuiteLifecycleVMName -Location $VMCluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin -InventoryLocation (Get-Folder $VMFolder)

        My-Logger "Powering On $AriaSuiteLifecycleVMName ..."
        $vm | Start-Vm -RunAsync | Out-Null

        Disconnect-VIServer * -Confirm:$false | Out-Null

        My-Logger "Waiting for Aria Suite Lifecycle Manager to be ready ..."
        while(1) {
            try {
                $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/bootstrap/api/status" -Method GET -SkipCertificateCheck -TimeoutSec 5

                if($requests.StatusCode -eq 200) {
                    My-Logger "Aria Suite Lifecycle Manager is now ready!"
                    break
                }
            }
            catch {
                My-Logger "Aria Suite Lifecycle Manager is not ready yet, sleeping for 5 minutes ..."
                sleep 300
            }
        }
    }
}

if($verifyAriaOVAUPload -eq 1) {
    # Verify Aria OVA have been uploaded
    My-Logger "Verifying Aria OVAs have been uploaded to ${AriaProductRepoPath} on Aria Suite Lifecycle Manager ..."

    $ovas = @($AriaOperationsOVAFilename,$AriaLogsOVAFilename,$AriaIdentityOVAFilename,$AriaAutomationOVAFilename)

    Connect-VIServer -Server $vCenterServerFQDN -User $vCenterUsername -Password $vCenterPassword | Out-Null
    $vm = Get-VM $AriaSuiteLifecycleVMName

    # automatically create repo directory for user
    $output = Invoke-VMScript -VM $vm -ScriptText "mkdir -p ${AriaProductRepoPath}" -GuestUser root -GuestPassword $AriaSuiteLifecycleRootPassword

    foreach ($ova in $ovas) {
        if($ova -ne "") {
            $output = Invoke-VMScript -VM $vm -ScriptText "ls ${AriaProductRepoPath}/${ova}" -GuestUser root -GuestPassword $AriaSuiteLifecycleRootPassword

            if($output.toString() -match "cannot") {
                Disconnect-VIServer * -Confirm:$false | Out-Null
                Write-Error "${ova} has not been uploaded to ${AriaProductRepoPath}"
                exit
            }
        }
    }

    Disconnect-VIServer * -Confirm:$false | Out-Null
}

if($changeAdminPassword -eq 1) {
    My-Logger "Changing the default password for admin@local ..."
    try {
        $json = @{
            "username" = "admin@local"
            "password" = $AriaSuiteLifecycleAdminPassword
        }

        $body = $json | ConvertTo-Json -Depth 2
        $method = "PUT"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/authzn/api/firstboot/updatepassword"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $pair = "admin@local:vmware"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)

        $headers = @{
            "Authorization"="basic $base64"
            "Content-Type"="application/json"
            "Accept"="application/json"
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "admin@local password change successful!"
        }
    } catch {
        Write-Error "Failed to change default password for admin@local ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($confirmNewAriaCreds -eq 1) {
    My-Logger "Logging into Aria Suite Lifecycle Manager using new credetials ..."
    try {
        $pair = "admin@local:$AriaSuiteLifecycleAdminPassword"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)

        $headers = @{
            "Authorization"="basic $base64"
            "Content-Type"="application/json"
            "Accept"="application/json"
        }

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/authzn/api/login"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers

        if($requests.StatusCode -eq 200) {
            My-Logger "Successfully logged in"
        }
    } catch {
        Write-Error "Failed to login using new credentials ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }

    $global:ariaSuiteLifecycleHeaders = $headers
}

if($configAriaProductRepo -eq 1) {
    My-Logger "Configuring Aria Product Repo settings ..."
    try {
        $json = @{
            "sourceType" = "Local"
            "sourceLocation" = $AriaProductRepoPath
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/product-binaries"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Aria Product Repo setings saved"
        }
    } catch {
        Write-Error "Failed to configure Aria Product Repo settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaProductDownloadBinary -eq 1) {
    My-Logger "Configuring Aria Product binary mapping settings ..."
    try {

        $json = @()
        if($AriaIdentityOVAFilename -ne "") {
            $tmp = @{
                "name" = $AriaIdentityOVAFilename
                "filePath" = "${AriaProductRepoPath}/${AriaIdentityOVAFilename}"
                "type" = "install"
            }
            $json += $tmp
        }

        if($AriaOperationsOVAFilename -ne "" -and $AriaOperationsLicenseKey -ne "") {
            $tmp = @{
                "name" = $AriaOperationsOVAFilename
                "filePath" = "${AriaProductRepoPath}/${AriaOperationsOVAFilename}"
                "type" = "install"
            }
            $json += $tmp
        }

        if($AriaLogsOVAFilename -ne "" -and $AriaLogsLicenseKey -ne "") {
            $tmp = @{
                "name" = $AriaLogsOVAFilename
                "filePath" = "${AriaProductRepoPath}/${AriaLogsOVAFilename}"
                "type" = "install"
            }
            $json += $tmp
        }

        if($AriaAutomationOVAFilename -ne "" -and $AriaAutomationLicenseKey -ne "") {
            $tmp = @{
                "name" = $AriaAutomationOVAFilename
                "filePath" = "${AriaProductRepoPath}/${AriaAutomationOVAFilename}"
                "type" = "install"
            }
            $json += $tmp
        }

        # Handle stupid scenario where single item isn't properly supported by API
        if($json.count -eq 1) {
            $tempBody = $json | ConvertTo-Json -Depth 4
            $body = '['+$tempBody+']'
        } else {
            $body = $json | ConvertTo-Json -Depth 4
        }

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/product-binaries/download"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Aria Product binary mapping setings saved"

            $requesId = ($requests | ConvertFrom-Json).requestId

            while(1) {
                $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/request/api/v2/requests/${requesId}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

                if(($requests | ConvertFrom-Json).state -ne "COMPLETED") {
                    My-Logger "Waiting for product mapping to complete, sleeping for 120 seconds"
                    Start-Sleep -Seconds 120
                } else {
                    My-Logger "Successfully completed product mapping"
                    break
                }
            }
        }
    } catch {
        Write-Error "Failed to configure Aria Product binary mapping settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaProductNTP -eq 1) {
    My-Logger "Configuring Aria Product NTP settings ..."
    try {
        $json = @{
            "name" = $VMNTP
            "hostName" = $VMNTP
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/ntp-servers"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "NTP setings saved"
        }
    } catch {
        Write-Error "Failed to configure NTP settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaProductDNS -eq 1) {
    My-Logger "Configuring Aria Product DNS settings ..."
    try {
        $json = @{
            "name" = $VMDNS
            "hostName" = $VMDNS
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/dns"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "DNS setings saved"
        }
    } catch {
        Write-Error "Failed to configure DNS settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}


if($configAriaProductCredentials -eq 1) {
    My-Logger "Configuring Aria Product Credential settings ..."
    try {
        $json = @{
            "alias" = $AriaProductCredentialAlias
            "userName" = $AriaProductDefaultUserName
            "password" = $AriaProductDefaultPassword
            "passwordDescription" = "Default password for Aria user $AriaProductDefaultUserName"
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Credential setings saved"
        }
    } catch {
        Write-Error "Failed to configure Credential settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configvCenterCredentials -eq 1) {
    My-Logger "Configuring vCenter Server Credential settings ..."
    try {
        $json = @{
            "alias" = $vCenterCredentialAlias
            "userName" = $vCenterUsername
            "password" = $vCenterPassword
            "passwordDescription" = "assword vCenter Server user $vCenterUsername"
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Credential setings saved"
        }
    } catch {
        Write-Error "Failed to configure Credential settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaDiskExpansion -eq 1) {
    My-Logger "Expanding /data partition on Aria Lifecycle Manager ..."
    try {
        # Get vCenter Password
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).passwords) {
                if($item.alias -eq $vCenterCredentialAlias) {
                    $vcPassword = $item
                    break
                }
            }
        }

        $json = @{
            "diskSizeInGb" = $diskExpansionInGB
            "vCenterHost" = $vCenterServerFQDN
            "vcUsername" = $vcPassword.userName
            "vcPassword" = "locker:password:$(${vcPassword}.vmid):$(${vcPassword}.alias)"
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/system-details/disks/expand"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            $requesId = ($requests | ConvertFrom-Json).requestId

            while(1) {
                $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/request/api/v2/requests/${requesId}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

                if(($requests | ConvertFrom-Json).state -ne "COMPLETED") {
                    My-Logger "Waiting for operation to complete, sleeping for 30 seconds"
                    Start-Sleep -Seconds 30
                } else {
                    My-Logger "Successfully expanded /data partition"
                    break
                }
            }
        }
    } catch {
        Write-Error "Failed to expand /data partition ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaLicenses -eq 1) {
    My-Logger "Configuring Aria Licensing settings ..."
    try {
        $licenses = @{
            $AriaOperationsLicenseAlias = $AriaOperationsLicenseKey
            $AriaLogsLicenseAlias = $AriaLogsLicenseKey
            $AriaAutomationLicenseAlias = $AriaAutomationLicenseKey
        }

        foreach ($license in $licenses.keys) {
            if($licenses[$license] -ne "") {
                $json = @{
                    "alias" = $license
                    "serialKey" = $licenses[$license]
                }

                $body = $json | ConvertTo-Json -Depth 2

                $method = "POST"
                $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/license/validate-and-add"

                if($debug) {
                    "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
                    "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
                }

                $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

                if($requests.StatusCode -eq 200) {
                    $requesId = ($requests | ConvertFrom-Json).requestId

                    while(1) {
                        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/request/api/v2/requests/${requesId}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

                        if(($requests | ConvertFrom-Json).state -ne "COMPLETED") {
                            My-Logger "Waiting to validate $license, sleeping for 30 seconds"
                            Start-Sleep -Seconds 30
                        } else {
                            My-Logger "Successfully added $license"
                            break
                        }
                    }
                }
            }
        }
    } catch {
        Write-Error "Failed to configure Licensing settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaDatacenter -eq 1) {
    My-Logger "Configuring Aria Datacenter settings ..."
    try {
        $json = @{
            "dataCenterName" = $AriaDatacenterName
            "primaryLocation" = $AriaDatacenterLocation
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Aria Datacenter setings saved"
        }
    } catch {
        Write-Error "Failed to configure Aria Datacenter settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriavCenter -eq 1) {
    My-Logger "Configuring Aria vCenter Server settings ..."
    try {
        # Get Datacenter ID
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Retreiving Aria Datacenter Id ..."

            foreach ($datacenter in ($requests | ConvertFrom-Json)) {
                if($datacenter.dataCenterName -eq $AriaDatacenterName) {
                    My-Logger "Successfully found Aria Datacenter Id ..."
                    $datacenterId = $datacenter.dataCenterVmid
                    break
                }
            }
        }

        # Get Password ID
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Retreiving vCenter Server Password Id ..."

            foreach ($password in ($requests | ConvertFrom-Json).passwords) {
                if($password.alias -eq $vCenterCredentialAlias) {
                    My-Logger "Successfully found vCenter Server password Id ..."
                    $vcPassword = $password
                    break
                }
            }
        }

        if($datacenterId -ne $null -and $vcPassword -ne $null) {
            $json = @{
                "vCenterHost" = $vCenterServerFQDN
                "vCenterName" = $vCenterServerFQDN
                "vcPassword" = "locker:password:$(${vcPassword}.vmid):$(${vcPassword}.alias)"
                "vcUsedAs" = "MANAGEMENT"
                "vcUsername" = $vcPassword.userName
            }

            $body = $json | ConvertTo-Json -Depth 2

            $method = "POST"
            $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters/${datacenterId}/vcenters"

            if($debug) {
                "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
                "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
            }

            $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

            if($requests.StatusCode -eq 200) {
                $requesId = ($requests | ConvertFrom-Json).requestId

                while(1) {
                    $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/request/api/v2/requests/${requesId}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

                    if(($requests | ConvertFrom-Json).state -ne "COMPLETED") {
                        My-Logger "Waiting for vCenter Server discovery to complete, sleeping for 30 seconds"
                        Start-Sleep -Seconds 30
                    } else {
                        My-Logger "Successfully added vCenter Server"
                        break
                    }
                }
            }
        } else {
            Write-Error "Unable to retrieve datacenterId and/or vcPassword"
        }
    } catch {
        Write-Error "Failed to configure Aria vCenter Server settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriavCertificates -eq 1) {
    My-Logger "Configuring Aria Product Certificate settings ..."
    try {
        $json = @{
            "alias" = $AriaProductCertificateAlias
            "c" = $AriaProductCertificateCountry
            "cN" = $AriaProductCertificateCN
            "host" = $AriaProductCertificateDomain
            "ip" = $AriaProductCertificateIP
            "l" = $AriaProductCertificateLocale
            "o" = $AriaProductCertificateOrganization
            "oU" = $AriaProductCertificateOU
            "sT" = $AriaProductCertificateState
            "size" = $AriaProductCertificateKeyLength
            "validity" = $AriaProductCertificateKeyValidity
        }

        $body = $json | ConvertTo-Json -Depth 2

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/certificates"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            My-Logger "Aria Product Certificate setings saved"
        }
    } catch {
        Write-Error "Failed to configure Aria Product Certificate settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaIdentityEnv -eq 1) {
    My-Logger "Configuring Aria Identity Manager Environment settings ..."
    try {
        My-Logger "Retreiving infrastructure deployment info ..."

        # Get Certificate
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/certificates" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).certificates) {
                if($item.alias -eq $AriaProductCertificateAlias) {
                    $certificate = $item
                    break
                }
            }
        }

        # Get Aria Datacenter
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json)) {
                if($item.dataCenterName -eq $AriaDatacenterName) {
                    $ariDatacenter = $item
                    break
                }
            }
        }

        # Get vCenter
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters/$(${ariDatacenter}.dataCenterVmid)/vcenters/${vCenterServerFQDN}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json)) {
                if($item.vCenterHost -eq $vCenterServerFQDN) {
                    $vcenter = $item
                    break
                }
            }
        }

        # Get Cluster
        $cluster = ($vcenter.vCDataCenters | where {$_.vcDataCenterName -eq $VMDatacenter}).clusters | where {$_.clusterName -eq $VMCluster}

        # Get Aria Password
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).passwords) {
                if($item.alias -eq $AriaProductCredentialAlias) {
                    $ariaPassword = $item
                    break
                }
            }
        }

        # Get vCenter Password
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).passwords) {
                if($item.alias -eq $vCenterCredentialAlias) {
                    $vcPassword = $item
                    break
                }
            }
        }

        # Get Aria Product
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/product-binaries" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
        foreach ($item in ($requests | ConvertFrom-Json)) {
            switch($item.productId) {
                "vidm" {
                    $ariaIdtProduct = $item
                    break
                }
            }
        }
    }

        $json = [ordered] @{
            "environmentId" = "globalenvironment"
            "environmentName" = "globalenvironment"
            "environmentDescription" = "Automated Aria Identity Deployment by William Lam"
            "infrastructure" = [ordered] @{
                "properties" = [ordered] @{
                    "acceptEULA" = "true"
                    "adminEmail" = "admin@primp-indusries.com"
                    "certificate" = "locker:certificate:$(${certificate}.vmid):$(${certificate}.alias)"
                    "cluster" = "${VMDatacenter}#${VMCluster}"
                    "dataCenterVmid" = $ariDatacenter.dataCenterVmid
                    "defaultPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                    "diskMode" = "thin"
                    "dns" = $VMDNS
                    "domain" = $VMDomain
                    "enableTelemetry" = "false"
                    "folderName" = $VMFolder
                    "gateway" = $VMGateway
                    "netmask" = $VMNetmask
                    "network" = $VMNetwork
                    "ntp" = $VMNTP
                    "resourcePool" = $VMResourePool
                    "searchpath" = $VMDomain
                    "storage" = $VMDatastore
                    "timeSyncMode" = "ntp"
                    "vCenterHost" = $vCenterServerFQDN
                    "vCenterName" = $vCenterServerFQDN
                    "vcPassword" = "locker:password:$(${vcPassword}.vmid):$(${vcPassword}.alias)"
                    "vcUsername" = ${vcPassword}.userName
                }
            }
            "products" = @(
                [ordered] @{
                    "id" = $ariaIdtProduct.productId
                    "version" = $ariaIdtProduct.productVersion
                    "properties" = [ordered] @{
                        "certificate" = "locker:certificate:$(${certificate}.vmid):$(${certificate}.alias)"
                        "vidmAdminPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                        "defaultConfigurationPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                        "defaultConfigurationUsername" = $AriaIdentityConfigUsername
                        "defaultConfigurationEmail" = $AriaIdentityConfigEmail
                        "nodeSize" = $AriaIdentityNodeSize
                        "configureClusterVIP" = "false"
                        "ntp" = $VMNTP
                        "timeSyncMode" = "ntp"
                    }
                    "nodes" = @(
                        @{
                            "type" = "vidm-primary"
                            "properties" = @{
                                "vmName" = $AriaIdentityVMName
                                "hostName" =  "$($AriaIdentityHostname).$($VMDomain)"
                                "ip" = $AriaIdentityIP
                            }
                        }
                    )
                }
            )
        }

        $body = $json | ConvertTo-Json -Depth 10

        $method = "POST"
        $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/environments"

        if($debug) {
            "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
            "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            $requesId = ($requests | ConvertFrom-Json).requestId

            My-Logger "Aria Identity Environment settings configured, deployment will now begin ..."
            while(1) {
                $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/request/api/v2/requests/${requesId}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

                if(($requests | ConvertFrom-Json).state -ne "COMPLETED") {
                    My-Logger "Waiting for Aria Identity to be ready, sleeping for 5 minutes"
                    Start-Sleep -Seconds 300
                } else {
                    My-Logger "Successfully deployed Aria Identity Manager"
                    break
                }
            }
        }

    } catch {
        Write-Error "Failed to configure Aria Identity Environment settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}

if($configAriaProductEnv -eq 1) {
    My-Logger "Configuring Aria Product Environment settings ..."
    try {
        My-Logger "Retreiving infrastructure deployment info ..."

        # Get Certificate
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/certificates" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).certificates) {
                if($item.alias -eq $AriaProductCertificateAlias) {
                    $certificate = $item
                    break
                }
            }
        }

        # Get Aria Datacenter
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json)) {
                if($item.dataCenterName -eq $AriaDatacenterName) {
                    $ariDatacenter = $item
                    break
                }
            }
        }

        # Get vCenter
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/datacenters/$(${ariDatacenter}.dataCenterVmid)/vcenters/${vCenterServerFQDN}" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json)) {
                if($item.vCenterHost -eq $vCenterServerFQDN) {
                    $vcenter = $item
                    break
                }
            }
        }

        # Get Cluster
        $cluster = ($vcenter.vCDataCenters | where {$_.vcDataCenterName -eq $VMDatacenter}).clusters | where {$_.clusterName -eq $VMCluster}

        # Get Aria Password
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).passwords) {
                if($item.alias -eq $AriaProductCredentialAlias) {
                    $ariaPassword = $item
                    break
                }
            }
        }

        # Get vCenter Password
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/passwords" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
            foreach ($item in ($requests | ConvertFrom-Json).passwords) {
                if($item.alias -eq $vCenterCredentialAlias) {
                    $vcPassword = $item
                    break
                }
            }
        }

        # Get Aria Product
        $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/settings/product-binaries" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
        if($requests.StatusCode -eq 200) {
        foreach ($item in ($requests | ConvertFrom-Json)) {
            switch($item.productId) {
                "vrops" {$ariaOpsProduct = $item}
                "vrli" {$ariaLogsProduct = $item}
                "vra" {$ariaAtmProduct = $item}
            }
        }

        $products = @()

        # Configure Aria Operations
        if($AriaOperationsLicenseKey -ne "") {
            My-Logger "Adding Aria Operations to deployment settings ..."
            $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/licenses" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
            if($requests.StatusCode -eq 200) {
                foreach ($item in ($requests | ConvertFrom-Json)) {
                    if($item.alias -eq $AriaOperationsLicenseAlias) {
                        $ariaOpsLicense = $item

                        $tmp = [ordered] @{
                            "id" = $ariaOpsProduct.productId
                            "version" = $ariaOpsProduct.productVersion
                            "properties" = [ordered] @{
                                "certificate" = "locker:certificate:$(${certificate}.vmid):$(${certificate}.alias)"
                                "productPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                                "licenseRef" = "locker:license:$(${ariaOpsLicense}.vmid):$(${ariaOpsLicense}.alias)"
                                "deployOption" = $AriaOperationsNodeSize
                                "ntp" = $VMNTP
                                "timeSyncMode" = "ntp"
                                "installSddcManagementPack" = "false"
                                "masterVidmEnabled" = "true"
                                "disableTls" = $AriaOperationsDisableTLS
                            }
                            "nodes" = @(
                                [ordered] @{
                                    "type" = "master"
                                    "properties" = @{
                                        "vmName" = $AriaOperationsVMName
                                        "hostName" =  "$($AriaOperationsHostname).$($VMDomain)"
                                        "ip" = $AriaOperationsIP
                                    }
                                }
                            )
                        }
                        $products+=$tmp

                        break
                    }
                }
            }
        }

        # Configure Aria Logs
        if($AriaLogsLicenseKey -ne "") {
            My-Logger "Adding Aria Operations for Logs to deployment settings ..."
            $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/licenses" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
            if($requests.StatusCode -eq 200) {
                foreach ($item in ($requests | ConvertFrom-Json)) {
                    if($item.alias -eq $AriaLogsLicenseAlias) {
                        $ariaLogsLicense = $item

                        $tmp = [ordered] @{
                            "id" = $ariaLogsProduct.productId
                            "version" = $ariaLogsProduct.productVersion
                            "properties" = [ordered] @{
                                "certificate" = "locker:certificate:$(${certificate}.vmid):$(${certificate}.alias)"
                                "productPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                                "licenseRef" = "locker:license:$(${ariaLogsLicense}.vmid):$(${ariaLogsLicense}.alias)"
                                "nodeSize" = $AriaLogsNodeSize
                                "configureClusterVIP" = "false"
                                "ntp" = $VMNTP
                                "timeSyncMode" = "ntp"
                            }
                            "nodes" = @(
                                [ordered] @{
                                    "type" = "vrli-master"
                                    "properties" = @{
                                        "vmName" = $AriaLogsVMName
                                        "hostName" =  "$($AriaLogsHostname).$($VMDomain)"
                                        "ip" = $AriaLogsIP
                                    }
                                }
                            )
                        }
                        $products+=$tmp

                        break
                    }
                }
            }
        }

        # Configure Aria Automation
        if($AriaAutomationLicenseKey -ne "") {
            My-Logger "Adding Aria Automation to deployment settings ..."
            $requests = Invoke-WebRequest -Uri "https://$($AriaSuiteLifecycleFQDN)/lcm/locker/api/v2/licenses" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body
            if($requests.StatusCode -eq 200) {
                foreach ($item in ($requests | ConvertFrom-Json)) {
                    if($item.alias -eq $AriaAutomationLicenseAlias) {
                        $ariaAtmLicense = $item

                        $tmp = [ordered] @{
                            "id" = $ariaAtmProduct.productId
                            "version" = $ariaAtmProduct.productVersion
                            "properties" = [ordered] @{
                                "certificate" = "locker:certificate:$(${certificate}.vmid):$(${certificate}.alias)"
                                "productPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                                "licenseRef" = "locker:license:$(${ariaAtmLicense}.vmid):$(${ariaAtmLicense}.alias)"
                                "nodeSize" = $AriaAutomationNodeSize
                                "configureClusterVIP" = "false"
                                "ntp" = $VMNTP
                                "timeSyncMode" = "ntp"
                                "vraK8ServiceCidr" = ""
                                "vraK8ClusterCidr" = ""
                                "monitorWithvROps" = "false"
                                "integrateWithSddcManager" = "false"
                                "vrliLogForwardingConfiguration" = "false"
                                "enablePendoSetting" = "false"
                            }
                            "nodes" = @(
                                [ordered] @{
                                    "type" = "vrava-primary"
                                    "properties" = @{
                                        "vmName" = $AriaAutomationVMName
                                        "hostName" =  "$($AriaAutomationHostname).$($VMDomain)"
                                        "ip" = $AriaAutomationIP
                                    }
                                }
                            )
                        }
                        $products+=$tmp

                        break
                    }
                }
            }
        }
    }
    $json = [ordered] @{
        "environmentName" = "Automated Aria Suite Deployment"
        "environmentDescription" = "Automated Aria Suite Deployment by William Lam"
        "infrastructure" = [ordered] @{
            "properties" = [ordered] @{
                "acceptEULA" = "true"
                "adminEmail" = "admin@primp-indusries.com"
                "certificate" = "locker:certificate:$(${certificate}.vmid):$(${certificate}.alias)"
                "cluster" = "${VMDatacenter}#${VMCluster}"
                "dataCenterVmid" = $ariDatacenter.dataCenterVmid
                "defaultPassword" = "locker:password:$(${ariaPassword}.vmid):$(${ariaPassword}.alias)"
                "diskMode" = "thin"
                "dns" = $VMDNS
                "domain" = $VMDomain
                "enableTelemetry" = "false"
                "folderName" = $VMFolder
                "gateway" = $VMGateway
                "netmask" = $VMNetmask
                "network" = $VMNetwork
                "ntp" = $VMNTP
                "resourcePool" = $VMResourePool
                "searchpath" = $VMDomain
                "storage" = $VMDatastore
                "timeSyncMode" = "ntp"
                "vCenterHost" = $vCenterServerFQDN
                "vCenterName" = $vCenterServerFQDN
                "vcPassword" = "locker:password:$(${vcPassword}.vmid):$(${vcPassword}.alias)"
                "vcUsername" = ${vcPassword}.userName
            }
        }
        "products" = $products
    }

    $body = $json | ConvertTo-Json -Depth 10

    $method = "POST"
    $uri = "https://$($AriaSuiteLifecycleFQDN)/lcm/lcops/api/v2/environments"

    if($debug) {
        "[DEBUG] - $method`n$uri`n" | Out-File -Append -LiteralPath $verboseLogFile
        "[DEBUG] - $body" | Out-File -Append -LiteralPath $verboseLogFile
    }

    $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $global:ariaSuiteLifecycleHeaders -Body $body

    if($requests.StatusCode -eq 200) {
        My-Logger "Aria Product Environment setings saved and deployment should begin shortly ... "
        My-Logger "You can monitor the progress of the deployment by logging into Aria Suite Lifecycle Manager"
    }

    } catch {
        Write-Error "Failed to configure Aria Environment settings ..."
        Write-Error "`n($_.Exception.Message)`n"
        break
    }
}