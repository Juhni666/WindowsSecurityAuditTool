@{
    ModuleVersion = '1.0.0'
    GUID = 'd3b5e1c4-7f9e-4c5e-8c3e-1c3d5e1f4b5a'
    Author = 'Your Name'
    CompanyName = 'Your Company'
    Copyright = 'Copyright © Your Company 2023'
    Description = 'This module contains helper functions for performing security audits on Windows systems.'
    FunctionsToExport = @('Safe-Run', 'Other-Function1', 'Other-Function2') # Add other functions as needed
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop')
    RequiredModules = @()
    FileList = @('AuditHelpers.psm1')
}