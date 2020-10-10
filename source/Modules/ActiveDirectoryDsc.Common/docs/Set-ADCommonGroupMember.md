
# Set-ADCommonGroupMember

## SYNOPSIS
Sets a member of an AD group by adding or removing its membership.

## SYNTAX

```
Set-ADCommonGroupMember [[-Members] <String[]>] [[-MembershipAttribute] <String>] [[-Parameters] <Hashtable>]
 [[-Action] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Set-ADCommonGroupMember function is used to add a member from the current or a different domain to or remove
it from an AD group.

## EXAMPLES

### EXAMPLE 1
```
Set-ADCommonGroupMember -Members 'cn=user1,cn=users,dc=contoso,dc=com' -MembershipAttribute 'DistinguishedName' -Parameters @{Identity='cn=group1,cn=users,dc=contoso,dc=com'}
```

## PARAMETERS

### -Action
Specifies what group membership action to take.
Valid options are 'Add' and 'Remove'.
Default value is 'Add'.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: Add
Accept pipeline input: False
Accept wildcard characters: False
```

### -Members
Specifies the members to add to or remove from the group.
These may be in the same domain as the group or in
alternate domains.

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

### -MembershipAttribute
Specifies the Active Directory attribute for the values of the Members parameter.
Default value is 'SamAccountName'.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: SamAccountName
Accept pipeline input: False
Accept wildcard characters: False
```

### -Parameters
Specifies the parameters to pass to the Resolve-MembersSecurityIdentifier and Set-ADGroup cmdlets when adding
the members to the group.
This should include the group Identity as well as Server and/or Credential.

```yaml
Type: System.Collections.Hashtable
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
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
Author refactored code: Jeremy Ciak (https://github.com/jeremyciak)

## RELATED LINKS
