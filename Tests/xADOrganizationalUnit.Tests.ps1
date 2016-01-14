[CmdletBinding()]
param()

if (!$PSScriptRoot) # $PSScriptRoot is not defined in 2.0
{
    $PSScriptRoot = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path $PSScriptRoot\..).Path

$ModuleName = 'MSFT_xADOrganizationalUnit'
Import-Module (Join-Path $RepoRoot "DSCResources\$ModuleName\$ModuleName.psm1") -Force;

Describe 'xADOrganizationalUnit' {
    
    InModuleScope $ModuleName {

        function Get-ADOrganizationalUnit { param ($Name) }
        function Set-ADOrganizationalUnit { param ($Identity, $Credential) }
        function Remove-ADOrganizationalUnit { param ($Name, $Credential) }
        function New-ADOrganizationalUnit { param ($Name, $Credential) }

        $testCredential = New-Object System.Management.Automation.PSCredential 'DummyUser', (ConvertTo-SecureString 'DummyPassword' -AsPlainText -Force);

        $testPresentParams = @{
            Name = 'TestOU'
            Path = 'OU=Fake,DC=contoso,DC=com';
            Description = 'Test AD OU description';
            Ensure = 'Present';
        }
        
        $testAbsentParams = $testPresentParams.Clone();
        $testAbsentParams['Ensure'] = 'Absent';
        
        $protectedFakeAdOu = @{
            Name = $testPresentParams.Name;
            ProtectedFromAccidentalDeletion = $true;
            Description = $testPresentParams.Description;
        }

        Context "Validate Get-TargetResource method" {

            It 'Returns a "System.Collections.Hashtable" object type' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                $targetResource = Get-TargetResource -Name $testPresentParams.Name -Path $testPresentParams.Path
                
                $targetResource -is [System.Collections.Hashtable] | Should Be $true
            }

            It 'Returns "Ensure" = "Present" when OU exists' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                $targetResource = Get-TargetResource -Name $testPresentParams.Name -Path $testPresentParams.Path
                
                $targetResource.Ensure | Should Be 'Present'
            }

            It 'Returns "Ensure" = "Absent" when OU does not exist' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { }
                $targetResource = Get-TargetResource -Name $testPresentParams.Name -Path $testPresentParams.Path
                
                $targetResource.Ensure | Should Be 'Absent'
            }

            It 'Returns "ProtectedFromAccidentalDeletion" = "$true" when OU is protected' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                $targetResource = Get-TargetResource -Name $testPresentParams.Name -Path $testPresentParams.Path
                
                $targetResource.ProtectedFromAccidentalDeletion | Should Be $true
            }

            It 'Returns "ProtectedFromAccidentalDeletion" = "$false" when OU is not protected' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith {
                    $unprotectedFakeAdOu = $protectedFakeAdOu.Clone();
                    $unprotectedFakeAdOu['ProtectedFromAccidentalDeletion'] = $false;
                    return [PSCustomObject] $unprotectedFakeAdOu
                }
                $targetResource = Get-TargetResource -Name $testPresentParams.Name -Path $testPresentParams.Path
                
                $targetResource.ProtectedFromAccidentalDeletion | Should Be $false
            }

            It 'Returns an empty description' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith {
                    $noDescriptionFakeAdOu = $protectedFakeAdOu.Clone();
                    $noDescriptionFakeAdOu['Description'] = '';
                    return [PSCustomObject] $noDescriptionFakeAdOu
                }

                $targetResource = Get-TargetResource -Name $testPresentParams.Name -Path $testPresentParams.Path

                $targetResource.Description | Should BeNullOrEmpty
            }

        } #end context Validate Get-TargetResource method
        
        Context "Validate Test-TargetResource method" {

            It 'Returns a "System.Boolean" object type' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit { return [PSCustomObject] $protectedFakeAdOu }
                $targetResource = Test-TargetResource @testPresentParams
                
                $targetResource -is [System.Boolean] | Should Be $true
            }

            It 'Fails when OU does not exist and "Ensure" = "Present"' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { }
                
                Test-TargetResource @testPresentParams | Should Be $false
            }

            It 'Fails when OU does exist and "Ensure" = "Absent"' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                
                Test-TargetResource @testAbsentParams | Should Be $false
            }

            It 'Fails when OU does exist but "Description" is incorrect' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit { return [PSCustomObject] $protectedFakeAdOu }
                $testDescriptionParams = $testPresentParams.Clone()
                $testDescriptionParams['Description'] = 'Wrong description'
                
                Test-TargetResource @testDescriptionParams | Should Be $false
            }

            It 'Fails when OU does exist but "ProtectedFromAccidentalDeletion" is incorrect' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit { return [PSCustomObject] $protectedFakeAdOu }
                $testProtectedFromAccidentalDeletionParams = $testPresentParams.Clone()
                $testProtectedFromAccidentalDeletionParams['ProtectedFromAccidentalDeletion'] = $false
                
                Test-TargetResource @testProtectedFromAccidentalDeletionParams | Should Be $false
            }

            It 'Passes when OU does exist, "Ensure" = "Present" and all properties are correct' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                
                Test-TargetResource @testPresentParams | Should Be $true
            }

            It 'Passes when OU does not exist and "Ensure" = "Absent"' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { }
                
                Test-TargetResource @testAbsentParams | Should Be $true
            }

            It 'Passes when no OU description is specified with existing OU description' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit { return [PSCustomObject] $protectedFakeAdOu }
                $testEmptyDescriptionParams = $testPresentParams.Clone()
                $testEmptyDescriptionParams['Description'] = ''
                
                Test-TargetResource @testEmptyDescriptionParams | Should Be $true
            }

        } #end Context Validate Test-TargetResource method
        
        Context "Validate Set-TargetResource method" {

            It 'Calls "New-ADOrganizationalUnit" when "Ensure" = "Present" and OU does not exist' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { }
                Mock New-ADOrganizationalUnit -ParameterFilter { $Name -eq $testPresentParams.Name } -MockWith { }
                
                Set-TargetResource @testPresentParams
                Assert-MockCalled New-ADOrganizationalUnit -ParameterFilter { $Name -eq $testPresentParams.Name } -Scope It
            }

            It 'Calls "New-ADOrganizationalUnit" with credentials when specified' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { }
                Mock New-ADOrganizationalUnit -ParameterFilter { $Credential -eq $testCredential } -MockWith { }
                
                Set-TargetResource @testPresentParams -Credential $testCredential
                Assert-MockCalled New-ADOrganizationalUnit -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

            It 'Calls "Set-ADOrganizationalUnit" when "Ensure" = "Present" and OU does exist' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                Mock Set-ADOrganizationalUnit -MockWith { }
                
                Set-TargetResource @testPresentParams
                Assert-MockCalled Set-ADOrganizationalUnit -Scope It
            }

            It 'Calls "Set-ADOrganizationalUnit" with credentials when specified' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                Mock Set-ADOrganizationalUnit -ParameterFilter { $Credential -eq $testCredential } -MockWith { }
                
                Set-TargetResource @testPresentParams -Credential $testCredential
                Assert-MockCalled Set-ADOrganizationalUnit -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

            It 'Calls "Remove-ADOrganizationalUnit" when "Ensure" = "Absent" and OU does exist but is unprotected' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith {
                    $unprotectedFakeAdOu = $protectedFakeAdOu.Clone()
                    $unprotectedFakeAdOu['ProtectedFromAccidentalDeletion'] = $false
                    return [PSCustomObject] $unprotectedFakeAdOu
                }
                Mock Remove-ADOrganizationalUnit -MockWith { }
                
                Set-TargetResource @testAbsentParams
                Assert-MockCalled Remove-ADOrganizationalUnit -Scope It
            }

            It 'Calls "Remove-ADOrganizationalUnit" when "Ensure" = "Absent" and OU does exist and is protected' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                Mock Remove-ADOrganizationalUnit -MockWith { }
                
                Set-TargetResource @testAbsentParams
                Assert-MockCalled Remove-ADOrganizationalUnit -Scope It
            }

            It 'Calls "Remove-ADOrganizationalUnit" with credentials when specified' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                Mock Remove-ADOrganizationalUnit -ParameterFilter { $Credential -eq $testCredential } -MockWith { }
                
                Set-TargetResource @testAbsentParams -Credential $testCredential
                Assert-MockCalled Remove-ADOrganizationalUnit -ParameterFilter { $Credential -eq $testCredential } -Scope It
            }

            It 'Calls "Set-ADOrganizationalUnit" when "Ensure" = "Absent", OU does exist but is protected' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith { return [PSCustomObject] $protectedFakeAdOu }
                Mock Remove-ADOrganizationalUnit -MockWith { }
                Mock Set-ADOrganizationalUnit -MockWith { }
                
                Set-TargetResource @testAbsentParams
                Assert-MockCalled Set-ADOrganizationalUnit -Scope It
            }

            It 'Does not call "Set-ADOrganizationalUnit" when "Ensure" = "Absent", OU does exist but is unprotected' {
                Mock Assert-Module -MockWith { }
                Mock Get-ADOrganizationalUnit -MockWith {
                    $unprotectedFakeAdOu = $protectedFakeAdOu.Clone()
                    $unprotectedFakeAdOu['ProtectedFromAccidentalDeletion'] = $false
                    return [PSCustomObject] $unprotectedFakeAdOu
                }
                Mock Remove-ADOrganizationalUnit -MockWith { }
                Mock Set-ADOrganizationalUnit -MockWith { }
                
                Set-TargetResource @testAbsentParams
                Assert-MockCalled Set-ADOrganizationalUnit -Scope It -Exactly 0
            }

        } #end context Validate Set-TargetResource method
    
    } #end InModuleScope
}
