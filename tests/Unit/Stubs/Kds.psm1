# Name: Kds
# Version: 1.0.0.0
# CreatedOn: 2020-04-19 13:18:44Z

Add-Type -IgnoreWarnings -TypeDefinition @'
public class _KDS_CONFIGURATION
{
    public bool IsSecondaryStubType = true;

    public _KDS_CONFIGURATION() { }
}

namespace Microsoft.KeyDistributionService.Cmdlets
{
    public class KdsRootKey
    {
        public bool IsSecondaryStubType = true;

        public KdsRootKey() { }
    }

    public class KdsServerConfiguration
    {
        // Constructor
        public KdsServerConfiguration(_KDS_CONFIGURATION serverConfig) { }

        // Property
        public System.String AttributeOfWrongFormat { get; set; }
        public System.Byte[] KdfParameters { get; set; }
        public System.Byte[] SecretAgreementParameters { get; set; }
        public System.Boolean IsValidFormat { get; set; }
        public System.String SecretAgreementAlgorithm { get; set; }
        public System.String KdfAlgorithm { get; set; }
        public System.Int32 SecretAgreementPublicKeyLength { get; set; }
        public System.Int32 SecretAgreementPrivateKeyLength { get; set; }
        public System.Int32 VersionNumber { get; set; }

        // Fabricated constructor
        private KdsServerConfiguration() { }
        public static KdsServerConfiguration CreateTypeInstance()
        {
            return new KdsServerConfiguration();
        }
    }

}

'@

function Add-KdsRootKey {
    <#
    .SYNOPSIS
        Add-KdsRootKey [[-EffectiveTime] <datetime>] [-LocalTestOnly] [<CommonParameters>]

Add-KdsRootKey -EffectiveImmediately [-LocalTestOnly] [<CommonParameters>]
    .PARAMETER LocalTestOnly
        Indicates that the new root key is generated on the local host only. This parameter is used with the Set-KdsConfiguration cmdlet to test the local server configuration.
        If this parameter is specified, then the cmdlet returns a value that indicates whether the test passed.
        If this parameter is not specified, then the cmdlet returns the identifier (ID) of the root key when the operation succeeds.
    .PARAMETER EffectiveTime
        Specifies the date on which the newly generated root key takes effect. If this parameter is not specified, the default date set is 10 days after the current date.
    .PARAMETER EffectiveImmediately
        Indicates that the Microsoft Group Key Distribution Service immediately uses the new root key.
    #>

    [CmdletBinding(DefaultParameterSetName='EffectiveTime', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [OutputType([System.Guid])]
    [OutputType([System.Boolean])]
    param (
        [switch]
        ${LocalTestOnly},

        [Parameter(ParameterSetName='EffectiveTime', Position=0, ValueFromPipeline=$true)]
        [datetime]
        ${EffectiveTime},

        [Parameter(ParameterSetName='EffectiveImmediately', Mandatory=$true)]
        [switch]
        ${EffectiveImmediately}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Clear-KdsCache {
    <#
    .SYNOPSIS
        Clear-KdsCache [[-CacheOwnerSid] <string>] [<CommonParameters>]
    .PARAMETER CacheOwnerSid
        Specifies the security identifier (SID) for the user account whose cache this cmdlet clears.
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [string]
        ${CacheOwnerSid}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-KdsConfiguration {
    <#
    .SYNOPSIS
        Get-KdsConfiguration [<CommonParameters>]
    #>

    [CmdletBinding()]
    [OutputType([Microsoft.KeyDistributionService.Cmdlets.KdsServerConfiguration])]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-KdsRootKey {
    <#
    .SYNOPSIS
        Get-KdsRootKey [<CommonParameters>]
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List`1[Microsoft.KeyDistributionService.Cmdlets.KdsRootKey]])]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-KdsConfiguration {
    <#
    .SYNOPSIS
        Set-KdsConfiguration [-LocalTestOnly] [-SecretAgreementPublicKeyLength <int>] [-SecretAgreementPrivateKeyLength <int>] [-SecretAgreementParameters <byte[]>] [-SecretAgreementAlgorithm <string>] [-KdfParameters <byte[]>] [-KdfAlgorithm <string>] [<CommonParameters>]

Set-KdsConfiguration -RevertToDefault [-LocalTestOnly] [<CommonParameters>]

Set-KdsConfiguration [-InputObject] <Object> [-LocalTestOnly] [<CommonParameters>]
    .PARAMETER LocalTestOnly
        Indicates that the cmdlet only validates the new group key distribution service configuration on the local computer, and does not store the key in Active Directory (AD).
        If this parameter is specified, then the cmdlet returns a value that indicates whether the test passed.
        If this parameter is not specified, then the cmdlet returns the new server configuration object.
    .PARAMETER SecretAgreementPublicKeyLength
        Specifies the length of the public key used in the secret agreement algorithm.
    .PARAMETER SecretAgreementPrivateKeyLength
        Specifies the length of the private key used in the secret agreement algorithm.
    .PARAMETER SecretAgreementParameters
        Specifies the parameters for the secret agreement algorithm. If this parameter is not specified or this parameter is set to $null, then no secret agreement algorithm parameters are needed.
    .PARAMETER SecretAgreementAlgorithm
        Specifies the name of the secret agreement algorithm used to generate a group public key.
    .PARAMETER KdfParameters
        Specifies the parameters for the key derivation function used to generate the group private key. If this parameter is not specified or this parameter is set to $null, then no key derivation function parameters are needed.
    .PARAMETER KdfAlgorithm
        Specifies the name of the key derivation function algorithm that the key distribution server uses to generate the keys.
    .PARAMETER RevertToDefault
        Indicates that the customized service configuration is reverted to the default configuration.
    .PARAMETER InputObject
        Specifies the server configuration object that contains the configuration information of the Microsoft Group KdsSvc.
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [OutputType([Microsoft.KeyDistributionService.Cmdlets.KdsServerConfiguration])]
    [OutputType([System.Boolean])]
    param (
        [switch]
        ${LocalTestOnly},

        [Parameter(ParameterSetName='KdsConfiguration', ValueFromPipelineByPropertyName=$true)]
        [int]
        ${SecretAgreementPublicKeyLength},

        [Parameter(ParameterSetName='KdsConfiguration', ValueFromPipelineByPropertyName=$true)]
        [int]
        ${SecretAgreementPrivateKeyLength},

        [Parameter(ParameterSetName='KdsConfiguration', ValueFromPipelineByPropertyName=$true)]
        [byte[]]
        ${SecretAgreementParameters},

        [Parameter(ParameterSetName='KdsConfiguration', ValueFromPipelineByPropertyName=$true)]
        [string]
        ${SecretAgreementAlgorithm},

        [Parameter(ParameterSetName='KdsConfiguration', ValueFromPipelineByPropertyName=$true)]
        [byte[]]
        ${KdfParameters},

        [Parameter(ParameterSetName='KdsConfiguration', ValueFromPipelineByPropertyName=$true)]
        [string]
        ${KdfAlgorithm},

        [Parameter(ParameterSetName='RevertToDefault', Mandatory=$true)]
        [switch]
        ${RevertToDefault},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Microsoft.KeyDistributionService.Cmdlets.KdsServerConfiguration]
        ${InputObject}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Test-KdsRootKey {
    <#
    .SYNOPSIS
        Test-KdsRootKey [-KeyId] <guid> [<CommonParameters>]
    .PARAMETER KeyId
        Specifies the ID of the root key to test.
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [guid]
        ${KeyId}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

