# Nutanix
Scripts for use with Nutanix APIs

## Invoke-VmShutdownByCategory
Example to run the script:
```PowerShell
$params = @{
    nxIP                 = "10.0.0.11"
    nxUser               = "admin"
    nxPassword           " "nutanix/4u"
    SkipCertificateCheck = $true
    categoryName         = "ShutdownGroup"
    categoryValue        = "A"
    clusterName          = "DC01-NX01"
    parallel             = $true
    quiet                = $false
}
.\Invoke-VmShutdownByCategory.ps1 @params

