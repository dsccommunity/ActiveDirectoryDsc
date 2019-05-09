# Localized resources for helper module xActiveDirectory.Common.

ConvertFrom-StringData @'
    PropertyTypeInvalidForDesiredValues = Property 'DesiredValues' must be either a [System.Collections.Hashtable], [CimInstance] or [PSBoundParametersDictionary]. The type detected was {0}.
    PropertyTypeInvalidForValuesToCheck = If 'DesiredValues' is a CimInstance, then property 'ValuesToCheck' must contain a value.
    PropertyValidationError = Expected to find an array value for property {0} in the current values, but it was either not present or was null. This has caused the test method to return false.
    PropertiesDoesNotMatch = Found an array for property {0} in the current values, but this array does not match the desired state. Details of the changes are below.
    PropertyThatDoesNotMatch = {0} - {1}
    ValueOfTypeDoesNotMatch = {0} value for property {1} does not match. Current state is '{2}' and desired state is '{3}'.
    UnableToCompareProperty = Unable to compare property {0} as the type {1} is not handled by the Test-DscParameterState cmdlet.
'@
