# # Suppressing this rule because Script Analyzer does not understand Pester's syntax.
# [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
# [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
# param ()

# BeforeDiscovery {
#     try
#     {
#         if (-not (Get-Module -Name 'DscResource.Test'))
#         {
#             # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
#             if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
#             {
#                 # Redirect all streams to $null, except the error stream (stream 2)
#                 & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 3>&1 4>&1 5>&1 6>&1 > $null
#             }

#             # If the dependencies has not been resolved, this will throw an error.
#             Import-Module -Name 'DscResource.Test' -Force -ErrorAction 'Stop'
#         }
#     }
#     catch [System.IO.FileNotFoundException]
#     {
#         throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -ResolveDependency -Tasks build" first.'
#     }
# }

# BeforeAll {
#     $script:dscModuleName = 'ActiveDirectoryDsc'
#     $script:dscResourceName = 'MSFT_ADDomainTrust'

#     $script:testEnvironment = Initialize-TestEnvironment `
#         -DSCModuleName $script:dscModuleName `
#         -DSCResourceName $script:dscResourceName `
#         -ResourceType 'Mof' `
#         -TestType 'Unit'

#     # Load stub cmdlets and classes.
#     Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Stubs\ActiveDirectory_2019.psm1')

#     $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscResourceName
#     $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscResourceName
#     $PSDefaultParameterValues['Should:ModuleName'] = $script:dscResourceName
# }

# AfterAll {
#     $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
#     $PSDefaultParameterValues.Remove('Mock:ModuleName')
#     $PSDefaultParameterValues.Remove('Should:ModuleName')

#     Restore-TestEnvironment -TestEnvironment $script:testEnvironment

#     # Unload stub module
#     Remove-Module -Name ActiveDirectory_2019 -Force

#     # Unload the module being tested so that it doesn't impact any other tests.
#     Get-Module -Name $script:dscResourceName -All | Remove-Module -Force
# }

# # $mockSourceDomainName = 'contoso.com'
# # $mockTargetDomainName = 'lab.local'

# # $mockCredentialUserName = 'COMPANY\User'
# # $mockCredentialPassword = ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
# # $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
# #     'COMPANY\User',
# #     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
# # )

# Describe 'MSFT_ADDomainTrust\Get-TargetResource' -Tag 'Get' {
#     BeforeAll {
#         $mockDefaultParameters = @{
#             SourceDomainName = 'contoso.com'
#             TargetDomainName = 'lab.local'
#             TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                 'COMPANY\User',
#                 ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#             )

#             TrustDirection   = 'Outbound'
#         }
#     }

#     Context 'When the system is in the desired state' {
#         Context 'When the domain trust is present in Active Directory' {
#             Context 'When the called with the TrustType ''External''' {
#                 BeforeAll {
#                     Mock -CommandName Get-TrustSourceAndTargetObject -MockWith {
#                         $mockTrustSource = New-Object -TypeName Object |
#                             Add-Member -MemberType ScriptMethod -Name 'GetTrustRelationship' -Value {
#                                 $script:getTrustRelationshipMethodCallCount += 1

#                                 return @{
#                                     TrustType      = 'Domain'
#                                     TrustDirection = 'Outbound'
#                                 }
#                             } -PassThru -Force

#                         $mockTrustTarget = New-Object -TypeName Object

#                         return $mockTrustSource, $mockTrustTarget
#                     }
#                 }

#                 BeforeEach {
#                     $script:getTrustRelationshipMethodCallCount = 0

#                     $mockGetTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $mockGetTargetResourceParameters['TrustType'] = 'External'
#                 }

#                 AfterEach {
#                     $script:getTrustRelationshipMethodCallCount | Should -Be 1

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }

#                 It 'Should return the state as present' {
#                     $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters

#                     $getTargetResourceResult.Ensure | Should -Be 'Present'
#                     $getTargetResourceResult.SourceDomainName | Should -Be $mockGetTargetResourceParameters.SourceDomainName
#                     $getTargetResourceResult.TargetDomainName | Should -Be $mockGetTargetResourceParameters.TargetDomainName
#                     $getTargetResourceResult.TargetCredential.UserName | Should -Be $mockCredential.UserName
#                     $getTargetResourceResult.TrustDirection | Should -Be $mockGetTargetResourceParameters.TrustDirection
#                     $getTargetResourceResult.TrustType | Should -Be $mockGetTargetResourceParameters.TrustType
#                     $getTargetResourceResult.AllowTrustRecreation | Should -BeFalse
#                 }

#                 Context 'When the called with the AllowTrustRecreation set to $true' {
#                     BeforeEach {
#                         $mockGetTargetResourceParameters['AllowTrustRecreation'] = $true
#                     }

#                     It 'Should return the same values as passed as parameters' {
#                         $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                         $getTargetResourceResult.Ensure | Should -Be 'Present'
#                         $getTargetResourceResult.SourceDomainName | Should -Be $mockGetTargetResourceParameters.SourceDomainName
#                         $getTargetResourceResult.TargetDomainName | Should -Be $mockGetTargetResourceParameters.TargetDomainName
#                         $getTargetResourceResult.TargetCredential.UserName | Should -Be $mockCredential.UserName
#                         $getTargetResourceResult.AllowTrustRecreation | Should -BeTrue
#                         $getTargetResourceResult.TrustDirection | Should -Be $mockGetTargetResourceParameters.TrustDirection
#                         $getTargetResourceResult.TrustType | Should -Be $mockGetTargetResourceParameters.TrustType
#                     }
#                 }
#             }

#             Context 'When the called with the TrustType ''Forest''' {
#                 BeforeAll {
#                     Mock -CommandName Get-TrustSourceAndTargetObject -MockWith {
#                         $mockTrustSource = New-Object -TypeName Object |
#                             Add-Member -MemberType ScriptMethod -Name 'GetTrustRelationship' -Value {
#                                 $script:getTrustRelationshipMethodCallCount += 1

#                                 return @{
#                                     TrustType      = 'Forest'
#                                     TrustDirection = 'Outbound'
#                                 }
#                             } -PassThru -Force

#                         $mockTrustTarget = New-Object -TypeName Object

#                         return $mockTrustSource, $mockTrustTarget
#                     }
#                 }

#                 BeforeEach {
#                     $script:getTrustRelationshipMethodCallCount = 0

#                     $mockGetTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $mockGetTargetResourceParameters['TrustType'] = 'Forest'
#                 }

#                 AfterEach {
#                     $script:getTrustRelationshipMethodCallCount | Should -Be 1

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }

#                 It 'Should return the state as present' {
#                     $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                     $getTargetResourceResult.Ensure | Should -Be 'Present'
#                 }

#                 It 'Should return the same values as passed as parameters' {
#                     $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                     $getTargetResourceResult.SourceDomainName | Should -Be $mockGetTargetResourceParameters.SourceDomainName
#                     $getTargetResourceResult.TargetDomainName | Should -Be $mockGetTargetResourceParameters.TargetDomainName
#                     $getTargetResourceResult.TargetCredential.UserName | Should -Be $mockCredential.UserName
#                 }

#                 It 'Should return the correct values for the other properties' {
#                     $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                     $getTargetResourceResult.TrustDirection | Should -Be $mockGetTargetResourceParameters.TrustDirection
#                     $getTargetResourceResult.TrustType | Should -Be $mockGetTargetResourceParameters.TrustType
#                     $getTargetResourceResult.AllowTrustRecreation | Should -BeFalse
#                 }
#             }
#         }

#         Context 'When the domain trust is absent from Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Get-TrustSourceAndTargetObject -MockWith {
#                     $mockTrustSource = New-Object -TypeName Object |
#                         Add-Member -MemberType ScriptMethod -Name 'GetTrustRelationship' -Value {
#                             $script:getTrustRelationshipMethodCallCount += 1

#                             throw
#                         } -PassThru -Force

#                     $mockTrustTarget = New-Object -TypeName Object

#                     return $mockTrustSource, $mockTrustTarget
#                 }
#             }

#             BeforeEach {
#                 $script:GetTrustRelationshipMethodCallCount = 0

#                 $mockGetTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $mockGetTargetResourceParameters['TrustType'] = 'Forest'
#             }

#             AfterEach {
#                 $script:getTrustRelationshipMethodCallCount | Should -Be 1

#                 Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#             }

#             It 'Should return the state as absent' {
#                 $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                 $getTargetResourceResult.Ensure | Should -Be 'Absent'
#             }

#             It 'Should return the same values as passed as parameters' {
#                 $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                 $getTargetResourceResult.SourceDomainName | Should -Be $mockGetTargetResourceParameters.SourceDomainName
#                 $getTargetResourceResult.TargetDomainName | Should -Be $mockGetTargetResourceParameters.TargetDomainName
#                 $getTargetResourceResult.TargetCredential.UserName | Should -Be $mockCredential.UserName
#             }

#             It 'Should return the correct values for the other properties' {
#                 $getTargetResourceResult = Get-TargetResource @mockGetTargetResourceParameters
#                 $getTargetResourceResult.TrustDirection | Should -BeNullOrEmpty
#                 $getTargetResourceResult.TrustType | Should -BeNullOrEmpty
#                 $getTargetResourceResult.AllowTrustRecreation | Should -BeFalse
#             }
#         }
#     }
# }

# Describe 'MSFT_ADDomainTrust\Test-TargetResource' -Tag 'Test' {
#     BeforeAll {
#         $mockDefaultParameters = @{
#             SourceDomainName = 'contoso.com'
#             TargetDomainName = 'lab.local'
#             TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                 'COMPANY\User',
#     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#             )
#         }
#     }

#     Context 'When the system is in the desired state' {
#         Context 'When the trust is absent from Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Compare-TargetResourceState -MockWith {
#                     return @(
#                         @{
#                             ParameterName  = 'Ensure'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustType'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustDirection'
#                             InDesiredState = $true
#                         }
#                     )
#                 }

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['Ensure'] = 'Absent'
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return $true' {
#                 $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
#                 $testTargetResourceResult | Should -BeTrue

#                 Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When the trust is present in Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Compare-TargetResourceState -MockWith {
#                     return @(
#                         @{
#                             ParameterName  = 'Ensure'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustType'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustDirection'
#                             InDesiredState = $true
#                         }
#                     )
#                 }

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return $true' {
#                 $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
#                 $testTargetResourceResult | Should -BeTrue

#                 Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
#             }
#         }
#     }

#     Context 'When the system is not in the desired state' {
#         Context 'When the trust should be absent from Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Compare-TargetResourceState -MockWith {
#                     return @(
#                         @{
#                             ParameterName  = 'Ensure'
#                             InDesiredState = $false
#                         }
#                         @{
#                             ParameterName  = 'TrustType'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustDirection'
#                             InDesiredState = $true
#                         }
#                     )
#                 }

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['Ensure'] = 'Absent'
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return $false' {
#                 $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
#                 $testTargetResourceResult | Should -BeFalse

#                 Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When the trust should be present in Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Compare-TargetResourceState -MockWith {
#                     return @(
#                         @{
#                             ParameterName  = 'Ensure'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustType'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustDirection'
#                             InDesiredState = $false
#                         }
#                     )
#                 }

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return $false' {
#                 $testTargetResourceResult = Test-TargetResource @testTargetResourceParameters
#                 $testTargetResourceResult | Should -BeFalse

#                 Should -Invoke -CommandName Compare-TargetResourceState -Exactly -Times 1 -Scope It
#             }
#         }
#     }
# }

# Describe 'MSFT_ADDomainTrust\Compare-TargetResourceState' -Tag 'Compare' {
#     BeforeAll {
#         $mockDefaultParameters = @{
#             SourceDomainName = 'contoso.com'
#             TargetDomainName = 'lab.local'
#             TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                 'COMPANY\User',
#     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#             )
#         }

#         $mockGetTargetResource_Absent = {
#             return @{
#                 Ensure           = 'Absent'
#                 SourceDomainName = 'contoso.com'
#                 TargetDomainName = 'lab.local'
#                 TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                     'COMPANY\User',
#     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#                 )
#                 TrustDirection   = $null
#                 TrustType        = $null
#             }
#         }

#         $mockGetTargetResource_Present = {
#             return @{
#                 Ensure           = 'Present'
#                 SourceDomainName = 'contoso.com'
#                 TargetDomainName = 'lab.local'
#                 TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                     'COMPANY\User',
#     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#                 )
#                 TrustDirection   = 'Outbound'
#                 TrustType        = 'External'
#             }
#         }
#     }

#     Context 'When the system is in the desired state' {
#         Context 'When the trust is absent from Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Absent

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['Ensure'] = 'Absent'
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return the correct values' {
#                 $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
#                 $compareTargetResourceStateResult | Should -HaveCount 1

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'Ensure' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'Absent'
#                 $comparedReturnValue.Actual | Should -Be 'Absent'
#                 $comparedReturnValue.InDesiredState | Should -BeTrue

#                 Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When the trust is present in Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return the correct values' {
#                 $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
#                 $compareTargetResourceStateResult | Should -HaveCount 3

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'Ensure' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'Present'
#                 $comparedReturnValue.Actual | Should -Be 'Present'
#                 $comparedReturnValue.InDesiredState | Should -BeTrue

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'TrustType' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'External'
#                 $comparedReturnValue.Actual | Should -Be 'External'
#                 $comparedReturnValue.InDesiredState | Should -BeTrue

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'TrustDirection' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'Outbound'
#                 $comparedReturnValue.Actual | Should -Be 'Outbound'
#                 $comparedReturnValue.InDesiredState | Should -BeTrue

#                 Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
#             }
#         }
#     }

#     Context 'When the system is not in the desired state' {
#         Context 'When the trust should be absent from Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['Ensure'] = 'Absent'
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return the correct values' {
#                 $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
#                 $compareTargetResourceStateResult | Should -HaveCount 1

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'Ensure' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'Absent'
#                 $comparedReturnValue.Actual | Should -Be 'Present'
#                 $comparedReturnValue.InDesiredState | Should -BeFalse

#                 Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When the trust should be present in Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Absent

#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'
#             }

#             It 'Should return the correct values' {
#                 $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
#                 $compareTargetResourceStateResult | Should -HaveCount 3

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'Ensure' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'Present'
#                 $comparedReturnValue.Actual | Should -Be 'Absent'
#                 $comparedReturnValue.InDesiredState | Should -BeFalse

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'TrustType' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'External'
#                 $comparedReturnValue.Actual | Should -BeNullOrEmpty
#                 $comparedReturnValue.InDesiredState | Should -BeFalse

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq 'TrustDirection' })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be 'Outbound'
#                 $comparedReturnValue.Actual | Should -BeNullOrEmpty
#                 $comparedReturnValue.InDesiredState | Should -BeFalse

#                 Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When a property is not in desired state' {
#             BeforeAll {
#                 Mock -CommandName Get-TargetResource -MockWith $mockGetTargetResource_Present


#                 # One test case per property with a value that differs from the desired state.
#                 $testCases_Properties = @(
#                     @{
#                         ParameterName = 'TrustType'
#                         Value         = 'Forest'
#                     },
#                     @{
#                         ParameterName = 'TrustDirection'
#                         Value         = 'Inbound'
#                     }
#                 )
#             }

#             It 'Should return the correct values when the property <ParameterName> is not in desired state' -TestCases $testCases_Properties {
#                 param
#                 (
#                     [Parameter()]
#                     $ParameterName,

#                     [Parameter()]
#                     $Value
#                 )

#                 # Set up all mandatory parameters to use the values in the mock.
#                 $testTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $testTargetResourceParameters['TrustType'] = 'External'
#                 $testTargetResourceParameters['TrustDirection'] = 'Outbound'

#                 # Change the property we are currently testing to a different value.
#                 $testTargetResourceParameters[$ParameterName] = $Value

#                 $compareTargetResourceStateResult = Compare-TargetResourceState @testTargetResourceParameters
#                 $compareTargetResourceStateResult | Should -HaveCount 3

#                 $comparedReturnValue = $compareTargetResourceStateResult.Where( { $_.ParameterName -eq $ParameterName })
#                 $comparedReturnValue | Should -Not -BeNullOrEmpty
#                 $comparedReturnValue.Expected | Should -Be $Value
#                 $comparedReturnValue.Actual | Should -Be (& $mockGetTargetResource_Present).$ParameterName
#                 $comparedReturnValue.InDesiredState | Should -BeFalse

#                 Should -Invoke -CommandName Get-TargetResource -Exactly -Times 1 -Scope It
#             }
#         }
#     }
# }

# Describe 'MSFT_ADDomainTrust\Set-TargetResource' -Tag 'Set' {
#     BeforeAll {
#         Mock -CommandName Get-TrustSourceAndTargetObject -MockWith {
#             $mockTrustSource = New-Object -TypeName Object |
#                 Add-Member -MemberType ScriptMethod -Name 'CreateTrustRelationship' -Value {
#                     $script:createTrustRelationshipMethodCallCount += 1
#                 } -PassThru |
#                 Add-Member -MemberType ScriptMethod -Name 'DeleteTrustRelationship' -Value {
#                     $script:deleteTrustRelationshipMethodCallCount += 1
#                 } -PassThru |
#                 Add-Member -MemberType ScriptMethod -Name 'UpdateTrustRelationship' -Value {
#                     $script:updateTrustRelationshipMethodCallCount += 1
#                 } -PassThru -Force

#             $mockTrustTarget = New-Object -TypeName Object

#             return $mockTrustSource, $mockTrustTarget
#         }

#         $mockDefaultParameters = @{
#             SourceDomainName = 'contoso.com'
#             TargetDomainName = 'lab.local'
#             TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                 'COMPANY\User',
#     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#             )
#             TrustDirection   = 'Outbound'
#         }
#     }

#     Context 'When the system is in the desired state' {
#         Context 'When the domain trust is present in Active Directory' {
#             Context 'When the called with the TrustType ''External''' {
#                 BeforeAll {
#                     Mock -CommandName Compare-TargetResourceState -MockWith {
#                         return @(
#                             @{
#                                 ParameterName  = 'Ensure'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustType'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustDirection'
#                                 InDesiredState = $true
#                             }
#                         )
#                     }
#                 }

#                 BeforeEach {
#                     $script:createTrustRelationshipMethodCallCount = 0
#                     $script:deleteTrustRelationshipMethodCallCount = 0
#                     $script:updateTrustRelationshipMethodCallCount = 0

#                     $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $setTargetResourceParameters['TrustType'] = 'External'
#                 }

#                 It 'Should not throw and not call any methods' {
#                     { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                     $script:createTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:deleteTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:updateTrustRelationshipMethodCallCount | Should -Be 0

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }
#             }

#             Context 'When the called with the TrustType ''Forest''' {
#                 BeforeAll {
#                     Mock -CommandName Compare-TargetResourceState -MockWith {
#                         return @(
#                             @{
#                                 ParameterName  = 'Ensure'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustType'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustDirection'
#                                 InDesiredState = $true
#                             }
#                         )
#                     }
#                 }

#                 BeforeEach {
#                     $script:createTrustRelationshipMethodCallCount = 0
#                     $script:deleteTrustRelationshipMethodCallCount = 0
#                     $script:updateTrustRelationshipMethodCallCount = 0

#                     $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $setTargetResourceParameters['TrustType'] = 'Forest'
#                 }

#                 It 'Should not throw and not call any methods' {
#                     { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                     $script:createTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:deleteTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:updateTrustRelationshipMethodCallCount | Should -Be 0

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }
#             }
#         }

#         Context 'When the domain trust is absent in Active Directory' {
#             Context 'When the called with the TrustType ''External''' {
#                 BeforeAll {
#                     Mock -CommandName Compare-TargetResourceState -MockWith {
#                         return @(
#                             @{
#                                 ParameterName  = 'Ensure'
#                                 InDesiredState = $true
#                             }
#                         )
#                     }
#                 }

#                 BeforeEach {
#                     $script:createTrustRelationshipMethodCallCount = 0
#                     $script:deleteTrustRelationshipMethodCallCount = 0
#                     $script:updateTrustRelationshipMethodCallCount = 0

#                     $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $setTargetResourceParameters['TrustType'] = 'External'
#                     $setTargetResourceParameters['Ensure'] = 'Absent'
#                 }

#                 It 'Should not throw and not call any methods' {
#                     { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                     $script:createTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:deleteTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:updateTrustRelationshipMethodCallCount | Should -Be 0

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }
#             }
#         }
#     }

#     Context 'When the system is not in the desired state' {
#         Context 'When the domain trust should be present in Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Compare-TargetResourceState -MockWith {
#                     return @(
#                         @{
#                             ParameterName  = 'Ensure'
#                             InDesiredState = $false
#                         }
#                         @{
#                             ParameterName  = 'TrustType'
#                             InDesiredState = $false
#                         }
#                         @{
#                             ParameterName  = 'TrustDirection'
#                             InDesiredState = $false
#                         }
#                     )
#                 }
#             }

#             BeforeEach {
#                 $script:createTrustRelationshipMethodCallCount = 0
#                 $script:deleteTrustRelationshipMethodCallCount = 0
#                 $script:updateTrustRelationshipMethodCallCount = 0

#                 $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $setTargetResourceParameters['TrustType'] = 'External'
#             }

#             It 'Should not throw and call the correct method' {
#                 { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                 $script:createTrustRelationshipMethodCallCount | Should -Be 1
#                 $script:deleteTrustRelationshipMethodCallCount | Should -Be 0
#                 $script:updateTrustRelationshipMethodCallCount | Should -Be 0

#                 Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When the domain trust should be absent from Active Directory' {
#             BeforeAll {
#                 Mock -CommandName Compare-TargetResourceState -MockWith {
#                     return @(
#                         @{
#                             ParameterName  = 'Ensure'
#                             InDesiredState = $false
#                         }
#                         @{
#                             ParameterName  = 'TrustType'
#                             InDesiredState = $true
#                         }
#                         @{
#                             ParameterName  = 'TrustDirection'
#                             InDesiredState = $true
#                         }
#                     )
#                 }
#             }

#             BeforeEach {
#                 $script:createTrustRelationshipMethodCallCount = 0
#                 $script:deleteTrustRelationshipMethodCallCount = 0
#                 $script:updateTrustRelationshipMethodCallCount = 0

#                 $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                 $setTargetResourceParameters['TrustType'] = 'External'
#                 $setTargetResourceParameters['Ensure'] = 'Absent'
#             }

#             It 'Should not throw and call the correct method' {
#                 { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                 $script:createTrustRelationshipMethodCallCount | Should -Be 0
#                 $script:deleteTrustRelationshipMethodCallCount | Should -Be 1
#                 $script:updateTrustRelationshipMethodCallCount | Should -Be 0

#                 Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#             }
#         }

#         Context 'When a property of a domain trust is not in desired state' {
#             Context 'When property TrustType is not in desired state, and not opt-in to recreate trust' {
#                 BeforeAll {
#                     Mock -CommandName Compare-TargetResourceState -MockWith {
#                         return @(
#                             @{
#                                 ParameterName  = 'Ensure'
#                                 Actual         = 'Present'
#                                 Expected       = 'Present'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustType'
#                                 Actual         = 'Domain'
#                                 Expected       = 'Forest'
#                                 InDesiredState = $false
#                             }
#                         )
#                     }
#                 }

#                 BeforeEach {
#                     $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $setTargetResourceParameters['TrustType'] = 'Forest'
#                     $setTargetResourceParameters['TrustDirection'] = 'Inbound'
#                 }

#                 It 'Should not throw and call the correct methods' {
#                     { Set-TargetResource @setTargetResourceParameters } | Should -Throw $script:localizedData.NotOptInToRecreateTrust

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }
#             }

#             Context 'When both properties TrustType and and TrustDirection is not in desired state' {
#                 BeforeAll {
#                     Mock -CommandName Compare-TargetResourceState -MockWith {
#                         return @(
#                             @{
#                                 ParameterName  = 'Ensure'
#                                 Actual         = 'Present'
#                                 Expected       = 'Present'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustType'
#                                 Actual         = 'Domain'
#                                 Expected       = 'Forest'
#                                 InDesiredState = $false
#                             }
#                             @{
#                                 ParameterName  = 'TrustDirection'
#                                 Actual         = 'Outbound'
#                                 Expected       = 'Inbound'
#                                 InDesiredState = $false
#                             }
#                         )
#                     }
#                 }

#                 BeforeEach {
#                     $script:createTrustRelationshipMethodCallCount = 0
#                     $script:deleteTrustRelationshipMethodCallCount = 0
#                     $script:updateTrustRelationshipMethodCallCount = 0

#                     $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $setTargetResourceParameters['TrustType'] = 'Forest'
#                     $setTargetResourceParameters['TrustDirection'] = 'Inbound'
#                     $setTargetResourceParameters['AllowTrustRecreation'] = $true
#                 }

#                 It 'Should not throw and call the correct methods' {
#                     { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                     $script:createTrustRelationshipMethodCallCount | Should -Be 1
#                     $script:deleteTrustRelationshipMethodCallCount | Should -Be 1
#                     $script:updateTrustRelationshipMethodCallCount | Should -Be 0

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }
#             }

#             Context 'When property TrustDirection is not in desired state' {
#                 BeforeAll {
#                     Mock -CommandName Compare-TargetResourceState -MockWith {
#                         return @(
#                             @{
#                                 ParameterName  = 'Ensure'
#                                 Actual         = 'Present'
#                                 Expected       = 'Present'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustType'
#                                 Actual         = 'Domain'
#                                 Expected       = 'Domain'
#                                 InDesiredState = $true
#                             }
#                             @{
#                                 ParameterName  = 'TrustDirection'
#                                 Actual         = 'Outbound'
#                                 Expected       = 'Inbound'
#                                 InDesiredState = $false
#                             }
#                         )
#                     }
#                 }

#                 BeforeEach {
#                     $script:createTrustRelationshipMethodCallCount = 0
#                     $script:deleteTrustRelationshipMethodCallCount = 0
#                     $script:updateTrustRelationshipMethodCallCount = 0

#                     $setTargetResourceParameters = $mockDefaultParameters.Clone()
#                     $setTargetResourceParameters['TrustType'] = 'External'
#                     $setTargetResourceParameters['TrustDirection'] = 'Inbound'
#                 }

#                 It 'Should not throw and call the correct method' {
#                     { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

#                     $script:createTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:deleteTrustRelationshipMethodCallCount | Should -Be 0
#                     $script:updateTrustRelationshipMethodCallCount | Should -Be 1

#                     Should -Invoke -CommandName Get-TrustSourceAndTargetObject -Exactly -Times 1 -Scope It
#                 }
#             }
#         }
#     }
# }

# Describe 'MSFT_ADDomainTrust\ConvertTo-DirectoryContextType' -Tag 'Helper' {
#     BeforeDiscovery {
#         $testCases = @(
#             @{
#                 TrustTypeValue            = 'External'
#                 DirectoryContextTypeValue = 'Domain'
#             },
#             @{
#                 TrustTypeValue            = 'Forest'
#                 DirectoryContextTypeValue = 'Forest'
#             }
#         )
#     }

#     It 'Should return the correct converted value for the trust type value <TrustTypeValue>' -TestCases $testCases {
#         InModuleScope -Parameters $_ -ScriptBlock {
#             Set-StrictMode -Version 1.0

#             ConvertTo-DirectoryContextType -TrustType $TrustTypeValue | Should -Be $DirectoryContextTypeValue
#         }
#     }

#     It 'Should return the correct converted value for the directory context type value <DirectoryContextTypeValue>' -TestCases $testCases {
#         InModuleScope -Parameters $_ -ScriptBlock {
#             Set-StrictMode -Version 1.0

#             ConvertFrom-DirectoryContextType -DirectoryContextType $DirectoryContextTypeValue | Should -Be $TrustTypeValue
#         }
#     }
# }

# Describe 'MSFT_ADDomainTrust\Get-TrustSourceAndTargetObject' -Tag 'Helper' {
#     BeforeAll {
#         Mock -CommandName Get-ADDirectoryContext -MockWith {
#             # This should work on any client, domain joined or not.
#             return [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain')
#         }

#         Mock -CommandName Get-ActiveDirectoryDomain
#         Mock -CommandName Get-ActiveDirectoryForest
#     }

#     BeforeDiscovery {
#         $testCases = @(
#             @{
#                 TrustType = 'External'
#             },
#             @{
#                 TrustType = 'Forest'
#             }
#         )
#     }

#     It 'Should not throw and call the correct mocks when called with the trust type value ''<TrustType>''' -TestCases $testCases {
#         InModuleScope -Parameters $_ -ScriptBlock {
#             Set-StrictMode -Version 1.0

#             $mockParameters = @{
#                 SourceDomainName = 'contoso.com'
#                 TargetDomainName = 'lab.local'
#                 TargetCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
#                     'COMPANY\User',
#                     ('dummyPassw0rd' | ConvertTo-SecureString -AsPlainText -Force)
#                 )
#                 TrustType        = $TrustType
#             }

#             { Get-TrustSourceAndTargetObject @mockParameters } | Should -Not -Throw

#             if ($TrustType -eq 'External')
#             {
#                 Should -Invoke -CommandName Get-ActiveDirectoryDomain -Exactly -Times 2 -Scope It
#             }
#             else
#             {
#                 Should -Invoke -CommandName Get-ActiveDirectoryForest -Exactly -Times 2 -Scope It
#             }
#         }
#     }
# }
