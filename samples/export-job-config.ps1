Import-Module .\vbrbasicrest.psm1
$rest = Get-VBRRestGUI

#Get-VBRRestHelp -r $rest -search "jobs/export"
$jobexport = Invoke-VBRRestMethod -r $rest -path "/api/v1/automation/jobs/export" -method post
$jobexport | ConvertTo-Json -Depth 100 | set-content job-export.json