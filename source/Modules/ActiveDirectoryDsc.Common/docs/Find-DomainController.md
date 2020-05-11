
# Find-DomainController

## SYNOPSIS
Finds an Active Directory domain controller.

## SYNTAX

```
Find-DomainController [-DomainName] <String> [[-SiteName] <String>] [[-Credential] <PSCredential>]
 [-WaitForValidCredentials] [<CommonParameters>]
```

## DESCRIPTION
The Find-DomainController function is used to find an Active Directory domain controller.
It returns a
DomainController object that represents the found domain controller.

## EXAMPLES

### EXAMPLE 1
```
Find-DomainController -DomainName contoso.com -SiteName Default -WaitForValidCredentials
```

## PARAMETERS

### -Credential
Specifies the credentials to use when accessing the domain, or use the current user if not specified.

```yaml
Type: System.Management.Automation.PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Specifies the fully qualified domain name.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SiteName
Specifies the site in the domain where to look for a domain controller.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WaitForValidCredentials
Specifies if authentication exceptions should be ignored.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.DirectoryServices.ActiveDirectory.DomainController
## NOTES
This function is designed so that it can run on any computer without having the ActiveDirectory module
installed.

## RELATED LINKS
