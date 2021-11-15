@{
    # Set up a mini virtual environment...
    PSDependOptions      = @{
        AddToPath  = $True
        Target     = 'output\RequiredModules'
        Parameters = @{
        }
    }

    invokeBuild                 = '5.8.0'
    PSScriptAnalyzer            = '1.19.1'
    pester                      = '4.10.1'
    Plaster                     = '1.1.3'
    ModuleBuilder               = '1.0.0'
    ChangelogManagement         = '2.1.4'
    Sampler                     = '0.111.6'
    'Sampler.GitHubTasks'       = '0.3.0'
    'DscResource.Common'        = '0.10.3'
    'DscResource.Test'          = '0.15.1'
    'DscResource.AnalyzerRules' = '0.2.0'
    xDscResourceDesigner        = '1.13.0.0'
    MarkdownLinkCheck           = '0.2.0'
    xFailoverCluster            = '1.14.1'
    # Required for PowerShell v 7.2+ as it has been split to a separate resource.
    'PSDesiredStateConfiguration' =@{
        Version = '2.0.5'
    }
}
