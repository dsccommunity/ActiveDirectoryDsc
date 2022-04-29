[DscResource(RunAsCredential='Optional')]
class InstallMSA {
    [DscProperty(Key)]
    [string] $MSAName

    [DscProperty()]
    [String] $Domain

    [DscProperty(NotConfigurable)]
    [Boolean] $MSATestResult

    [DscProperty(NotConfigurable)]
    [String] $MSAInstalledServers

    [DscProperty(NotConfigurable)]
    [String] $MSAExists

    [InstallMSA]get() {
        $ErrorActionPreference = 'silentlycontinue'
        $status = [InstallMSA]::new()
        # if a domain is not specified, use the target computer's domain
        $status.domain = (Get-WmiObject Win32_ComputerSystem).domain
        $status.MSAName = $this.MSAName
        # have to get all MSAs and then filter from there because of the dumbassery of AD cmdlet error handling
        $MSA = Get-ADServiceAccount -Filter 'cn -like "*"' -Properties "hostcomputers" -Server $status.Domain | Where-Object name -eq $this.MSAName
        if (!$MSA) {
            $status.MSAExists = $false
        }
        else {
            $status.MSAExists = $true
            $status.MSATestResult = Test-ADServiceAccount -Identity $this.MSAName -warningaction silentlycontinue # mute errors to limit message contamination on failed tests
            $status.MSAInstalledServers = $MSA.hostcomputers
        }
        return $status
    } # end get
    [void]set() {
        $status = $this.get()
        # if MSA doesn't exist
        if ($status.MSAExists -eq $false) {
            Write-Verbose "MSA could not be found on domain. A new MSA will be created, but permissions will need to be re-assigned"
            New-ADServiceAccount -Name $this.MSAName -RestrictToSingleComputer -Description "MSA created by DSC." -Server $status.Domain
        }
        # if MSA failed test
        if ($status.MSATestResult -eq $false) {
            Install-ADServiceAccount -Identity $this.MSAName
        }
    } # end set
    [bool]test() {
        $status = $this.get()
        Write-Verbose 'Confirming MSA exists'
        if (!$status.MSAName) {
            return $false
        }
        Write-Verbose 'Confirming MSA passed test'
        if ($Status.MSATestResult -like "False") {
            return $false
        }
        write-verbose 'Confirming MSA is in host computers list'
        if ($status.MSAInstalledServers -notmatch $env:COMPUTERNAME) {
            return $false
        }
        Write-Verbose 'node has passed all tests'
        return $true
    } # end test
} # end class
