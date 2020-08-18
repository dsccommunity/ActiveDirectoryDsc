
# Resolve-MembersSecurityIdentifier

## SYNOPSIS
Resolves the Security Identifier (SID) of a list of Members of the same type defined by the MembershipAttribute.

## SYNTAX

```
Resolve-MembersSecurityIdentifier [-Members] <String[]> [[-MembershipAttribute] <String>]
 [[-Parameters] <Hashtable>] [-PrepareForMembership] [<CommonParameters>]
```

## DESCRIPTION
The Resolve-MembersSecurityIdentifier function is used to get an array of System.String objects representing
the Security Identifier (SID) translated from the specified list of Members with a type defined by the
MembershipAttribute.
Custom logic is used for Foreign Security Principals to translate from a SamAccountName
or DistinguishedName, otherwise the value is sent to Get-ADObject as a filter to return the ObjectSID.

## EXAMPLES

### EXAMPLE 1
```
Get-ADGroup -Identity 'GroupName' -Properties 'Members' | Resolve-MembersSecurityIdentifier -MembershipAttribute 'DistinguishedName'
```

-----------
Description
This will translate all of the DistinguishedName values for the Members of 'GroupName' into SID values.

## PARAMETERS

### -Members
Specifies the MembershipAttribute type values representing the Members to resolve into a Security Identifier.

```yaml
Type: System.String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
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
Specifies the parameters to pass to the Resolve-MembersSecurityIdentifier cmdlet for usage with the internal
Get-ADObject call.
This is an optional parameter which can have Keys and Values for Server and Credential.

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

### -PrepareForMembership
Specifies whether to wrap each resulting value 'VALUE' as '\<SID=VALUE\>' so that it can be passed directly to
Set-ADGroup under the 'member' key in the hash object.

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

### System.String[]
## NOTES
This is a helper function to allow for easier one-way trust AD group membership management based on SID.
See issue https://github.com/dsccommunity/ActiveDirectoryDsc/issues/619 for more information.

## RELATED LINKS
