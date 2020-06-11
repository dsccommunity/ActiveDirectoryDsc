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
    pester                      = '4.10.1'
    Plaster                     = 'latest'
    ModuleBuilder               = '1.0.0'
    ChangelogManagement         = 'latest'
    Sampler                     = 'latest'
    'DscResource.Common'        = '0.5.0'
    'DscResource.Test'          = 'latest'
    'DscResource.AnalyzerRules' = 'latest'
    xDscResourceDesigner        = 'latest'
    MarkdownLinkCheck           = 'latest'
    xFailoverCluster            = '1.14.1'
}
