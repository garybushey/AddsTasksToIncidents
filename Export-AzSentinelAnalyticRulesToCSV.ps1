
#requires -version 6.2
<#
.SYNOPSIS

This command will generate a CSV file containing either the count of the Microsoft Sentinel
MITRE tactics and techniques being used or a list of the rules using the tactics and techniques
    .DESCRIPTION

        Based on the parameters used, this command will eitehr generate a CSV file containing the information about all the Microsoft Sentinel
        MITRE tactics and techniques being used, or a listing of the rules that use the tactics and techniques
    .PARAMETER WorkspaceName

        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName

        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName

        Enter the file name to use.  Defaults to "mitrerules" and ".csv" will be appended to all FileNames that do not already include it
    .NOTES

        AUTHOR= Gary Bushey
        LASTEDIT= 13 December 2022
    .EXAMPLE

        Export-AzSentineAnalyticRulesToCSV -WorkspaceName "WorkspaceName" -ResourceGroupName "rgname"
        In this example you will get the file named "Analyticrules.csv" generated containing the count of the active rule's MITRE information
    .EXAMPLE

        Export-AzSentineAnalyticRulesToCSV -WorkspaceName "WorkspaceName" -ResourceGroupName "rgname" -FileName "test"
        In this example you will get the file named "test.csv" generated containing  the count of the active rule's MITRE information
#>

[CmdletBinding()]
param (
  ## The name of the workspace.  Required
  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [string]$FileName = "analyticrules.csv"
)

Add-Type -AssemblyName System.Collections

$outputObject = New-Object system.Data.DataTable
[void]$outputObject.Columns.Add('RuleID', [string]::empty.GetType() )
[void]$outputObject.Columns.Add('RuleName', [string]::empty.GetType() )
[void]$outputObject.Columns.Add('TaskTemplates', [string]::empty.GetType() )



Function Export-AzSentineAnalyticRulesToCSV ($WorkspaceName, $ResourceGroupName, $FileName, $IncludeDisabled, $ShowRules, $ShowIncidents) {


  if (! $FileName.EndsWith(".csv")) {
    $FileName += ".csv"
  }
  #Setup the Authentication header needed for the REST callss
  $context = Get-AzContext
  $userProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
  $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($userProfile)
  $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
  $authHeader = @{
    'Content-Type'  = 'application/json' 
    'Authorization' = 'Bearer ' + $token.AccessToken 
  }
    
  $subscriptionId = (Get-AzContext).Subscription.Id
  $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)/providers/Microsoft.SecurityInsights/alertrules?api-version=2022-11-01-preview"

  $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

  foreach ($result in $results) {

    if ($result.name -ne "BuiltInFusion")
    {
      $newRow = $outputObject.NewRow()
      $newRow.RuleID = $result.name
      $newRow.RuleName = $result.properties.displayName
      $newRow.TaskTemplates = "[]"
    
      [void]$outputObject.Rows.Add( $newRow )
    }
  }
   
  $outputObject |  Export-Csv -QuoteFields "Description" -Path $FileName -Append
}

#Execute the code
Export-AzSentineAnalyticRulesToCSV $WorkspaceName $ResourceGroupName $FileName $IncludeDisabled $ShowRules $ShowIncidents
