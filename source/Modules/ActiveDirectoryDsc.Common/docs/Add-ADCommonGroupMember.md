
# Add-ADCommonGroupMember

## SYNOPSIS
Adds a member to an AD group.

## SYNTAX

```
Add-ADCommonGroupMember [[-Members] <String[]>] [[-Parameters] <Hashtable>] [-MembersInMultipleDomains]
 [<CommonParameters>]
```

## DESCRIPTION
The Add-ADCommonGroupMember function is used to add a member from the current or a different domain to an AD
group.

## EXAMPLES

### EXAMPLE 1
```
Add-ADCommonGroupMember -Members 'cn=user1,cn=users,dc=contoso,dc=com' -Parameters @{Identity='cn=group1,cn=users,dc=contoso,dc=com}
```

## PARAMETERS

### -Members
The members to add to the group.
These may be in the same domain as the group or in alternate domains.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MembersInMultipleDomains
Setting this switch indicates that there are members from alternate domains.
This triggers the identities of
the members to be looked up in the alternate domain.

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

### -Parameters
The parameters to pass to the Add-ADGroupMember cmdlet when adding the members to the group.
This should
include the group identity.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### None
## NOTES
Author original code: Robert D.
Biddle (https://github.com/RobBiddle)
Author refactored code: Jan-Hendrik Peters (https://github.com/nyanhp)

## RELATED LINKS
