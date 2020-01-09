@{
    # Set up a mini virtual environment...
    PSDependOptions      = @{
        AddToPath  = $True
        Target     = 'output\RequiredModules'
        Parameters = @{
        }
    }

    invokeBuild                 = 'latest'
    PSScriptAnalyzer            = 'latest'
    pester                      = 'latest'
    Plaster                     = 'latest'
    ModuleBuilder               = '1.0.0'
    ChangelogManagement         = 'latest'
    Sampler                     = 'latest'
    'DscResource.Test'          = 'latest'
    'DscResource.AnalyzerRules' = 'latest'
    xDscResourceDesigner        = 'latest'
    MarkdownLinkCheck           = 'latest'
    xFailoverCluster            = '1.14.1'


    # PSPKI                       = 'latest'
    # 'DscResource.Common' = @{
    #     Target     = 'Source/Modules'
    #     Version    = 'latest'
    # }
}
