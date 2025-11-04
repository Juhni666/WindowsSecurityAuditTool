$obj = [PSCustomObject]@{Points=5; Severity='High'; Category='Test'; Description='Sample'}
"Test: ($($obj.Points) points)" | Write-Output
"  [$($obj.Severity)] $($obj.Category) - $($obj.Description) ($($obj.Points) points)" | Write-Output
