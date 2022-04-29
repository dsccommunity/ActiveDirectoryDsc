[DscResource(RunAsCredential='Optional')]
class InstallGMSA {
    [DscProperty(Key)]
    [string] $GMSAName

    [DscProperty(Mandatory)]
    [String] $GMSAGroupName

    [DscProperty(Mandatory)]
    [String] $GMSAGroupPath

    [DscProperty(Mandatory)]
    [pscredential] $credential

    [DscProperty(Mandatory)]
    [String] $organizationalunit

    [DscProperty(NotConfigurable)]
    [String] $Domain

    [DscProperty(NotConfigurable)]
    [String] $GMSAExists

    [DscProperty(NotConfigurable)]
    [String] $GMSATestResult

    [DscProperty(NotConfigurable)]
    [String] $GMSAGroupMembership

    [DscProperty(NotConfigurable)]
    [String] $GMSAGroup

    [DscProperty(NotConfigurable)]
    [String] $GMSAGroupExists

    [DscProperty(NotConfigurable)]
    [String] $GMSAPrincipals

    [InstallGMSA]get() {
        $erroractionpreference = 'silentlycontinue'
        $status = [InstallGMSA]::new()
        # Get GMSA status, DN, group, group membership, and test results
        $status.domain = (Get-WmiObject Win32_ComputerSystem).domain
        $GMSAAccount = Get-ADServiceAccount -Filter 'cn -like "*"' -Properties PrincipalsAllowedToRetrieveManagedPassword -Server $status.Domain -Credential $this.credential | Where-Object name -eq $this.GMSAName
        $status.GMSAName = $this.GMSAName
        $status.GMSAGroup = Get-ADGroup -Filter 'cn -like "*"' -Server $status.Domain -Credential $this.credential | where-object name -eq $this.GMSAGroupname
        $status.GMSAGroupName = $this.GMSAGroupName

        if (!$GMSAAccount) {
            $status.GMSAExists = $false
        }
        else {
            $status.GMSAPrincipals = $GMSAAccount.PrincipalsAllowedToRetrieveManagedPassword
            $status.GMSATestResult = Test-ADServiceAccount -Identity $this.GMSAName -warningaction silentlycontinue
            $status.GMSAExists = $true
        }
        if (!$status.GMSAGroup) {
            $status.GMSAGroupExists = $false
        }
        else {
            $status.GMSAGroupMembership = Get-ADGroupMember -Identity $status.GMSAGroup -Server $status.Domain -Credential $this.credential
            $status.GMSAGroupExists = $true
        }
        return $status
    }
    [void]set() {
        $status = $this.get()
        # get a new kerberos ticket
        klist purge -li 0x3e7
        # GMSA exists
        if ($status.GMSAExists -eq $false) {
            Write-Verbose "GMSA could not be found on domain. A new GMSA will be created, but permissions will need to be re-assigned"
            New-ADServiceAccount -Name $this.GMSAName -Description "GMSA created by DSC." -Server $status.Domain -DNSHostName "$($this.GMSAName) + '.' + $($status.Domain)" -Credential $this.credential
            Write-Verbose "GMSA successfully created."
        }
        # GMSA group exists
        if ($status.GMSAGroupExists -eq $false) {
            Write-Verbose "Adding GMSA group"
            $newgroup = @{
                name = $this.GMSAGroupName
                SamAccountName = $this.GMSAGroupName
                GroupCategory = "Security"
                groupscope = "Global"
                description = "gMSA group for $($status.GMSAName)"
                displayname = $this.GMSAGroupName
                path = $this.GMSAGroupPath
                server = $status.Domain
                credential = $this.credential
            }
            $this.GMSAGroup = New-ADGroup @newgroup
            Write-Verbose "Group Created"
        } # end group doesn't exist
        # group can get password
        $status.GMSAPrincipals = (Get-ADServiceAccount -Filter 'cn -like "*"' -Properties PrincipalsAllowedToRetrieveManagedPassword -Server $status.Domain -Credential $this.credential | Where-Object name -eq $this.MSAName).PrincipalsAllowedToRetrieveManagedPassword
        Write-Verbose "Checking if GMSA group is missing from GMSA"
        if ($status.GMSAPrincipals -notcontains $status.GMSAGroup) {
            Write-Verbose "Group missing from GMSA. Assigning group to GMSA"
            Set-ADServiceAccount $this.GMSAName -Server $status.Domain -PrincipalsAllowedToRetrieveManagedPassword $this.GMSAGroupName -Credential $this.credential
        }
        # node is member of group
        Write-Verbose "Checking if node is member of the GMSA group"
        $status.GMSAGroupMembership = (Get-ADGroupMember -Identity $this.GMSAGroupName -Server $status.Domain -Credential $this.credential).name
        if ($status.GMSAGroupMembership -notcontains $env:COMPUTERNAME) {
            Write-Verbose "Node is not a member of the GMSA group. Adding."
            $member = Get-ADComputer -Identity $env:COMPUTERNAME -Server $status.Domain -Credential $this.credential
            Add-ADGroupMember -Identity $this.GMSAGroupName -Members $member -Server $status.Domain -Credential $this.credential
        }
    }
    [bool]test() {
        $status = $this.get()
        Write-Verbose 'Confirming GMSA Exists'
        if (!$status.GMSAExists) {
            Write-Verbose 'GMSA does not exist'
            return $false
        }
        Write-Verbose 'Confirming GMSA passes test'
        if ($status.GMSATestResult -like "False") {
            Write-Verbose 'GMSA passes test'
            return $false
        }
        Write-Verbose 'Confirming GMSA password principal is not null'
        if (!$status.GMSAPrincipals) {
            Write-Verbose 'GMSA password principal is null'
            return $false
        }
        Write-Verbose 'Confirming GMSA group exists'
        if (!$status.GMSAGroupExists) {
            Write-Verbose 'GMSA group does not exist'
            return $false
        }
        Write-Verbose 'Confirming GMSA group contains node'
        if ($status.GMSAGroupMembership -notmatch "CN=$env:COMPUTERNAME,") {
            Write-Verbose 'GMSA group does not contain node'
            return $false
        }
        Write-Verbose 'Node passed all GMSA tests!'
        return $true
    }
}
