
# Get-ADCommonParameters

## SYNOPSIS
Gets a common AD cmdlet connection parameter for splatting.

## SYNTAX

```
Get-ADCommonParameters [-Identity] <String> [[-CommonName] <String>] [[-Credential] <PSCredential>]
 [[-Server] <String>] [-UseNameParameter] [-PreferCommonName] [[-RemainingArguments] <Object>]
 [<CommonParameters>]
```

## DESCRIPTION
The Get-ADCommonParameters function is used to get a common AD cmdlet connection parameter for splatting.
A
hashtable is returned containing the derived connection parameters.

## EXAMPLES

### EXAMPLE 1
```
Get-CommonADParameters @PSBoundParameters
```

Returns connection parameters suitable for Get-ADUser using the splatted cmdlet parameters.

### EXAMPLE 2
```
Get-CommonADParameters @PSBoundParameters -UseNameParameter
```

Returns connection parameters suitable for New-ADUser using the splatted cmdlet parameters.

## PARAMETERS

### -CommonName
When specified, a CommonName overrides the Identity used as the Name key.
For example, the Get-ADUser,
Set-ADUser and Remove-ADUser cmdlets take an Identity parameter, but the New-ADUser cmdlet uses the Name
parameter.

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

### -Identity
Specifies the identity to use as the Identity or Name connection parameter.
Aliases are 'UserName',
'GroupName', 'ComputerName' and 'ServiceAccountName'.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: UserName, GroupName, ComputerName, ServiceAccountName, Name

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PreferCommonName
If specified along with a CommonName parameter, The CommonName will be used as the Identity or Name connection
parameter instead of the Identity parameter.

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

### -RemainingArguments
Catch all to enable splatted $PSBoundParameters

```yaml
Type: System.Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Specifies the name of the domain controller to use when accessing the domain.
If not specified, a domain
controller is discovered using the standard Active Directory discovery process.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: DomainController

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UseNameParameter
Specifies to return the Identity as the Name key.
For example, the Get-ADUser, Set-ADUser and Remove-ADUser
cmdlets take an Identity parameter, but the New-ADUser cmdlet uses the Name parameter.

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

### System.Collections.Hashtable
## NOTES

## RELATED LINKS
