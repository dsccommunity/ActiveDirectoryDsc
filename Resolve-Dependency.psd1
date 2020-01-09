@{ # Defaults Parameter value to be loaded by the Resolve-Dependency command (unless set in Bound Parameters)
    #PSDependTarget  = './output/modules'
    #Proxy = ''
    #ProxyCredential = '$MyCredentialVariable' #TODO: find a way to support credentials in build (resolve variable)
    Gallery         = 'PSGallery'
    # AllowOldPowerShellGetModule = $true
    #MinimumPSDependVersion = '0.3.0'
    AllowPrerelease = $false
    WithYAML        = $true # Will also bootstrap PowerShell-Yaml to read other config files
}
