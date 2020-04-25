---
external help file: ActiveDirectoryDsc.Common-help.xml
Module Name: ActiveDirectoryDsc.Common
online version:
schema: 2.0.0
---

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
{{ Fill Credential Description }}

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
{{ Fill Identity Description }}

```yaml
Type: System.String
Parameter Sets: (All)
Aliases: UserName, GroupName, ComputerName, ServiceAccountName

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PreferCommonName
{{ Fill PreferCommonName Description }}

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
{{ Fill Server Description }}

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
Returns the Identity as the Name key.
For example, the Get-ADUser, Set-ADUser and Remove-ADUser cmdlets
take an Identity parameter, but the New-ADUser cmdlet uses the Name parameter.

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
