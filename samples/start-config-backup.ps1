Import-Module .\vbrbasicrest.psm1
$rest = Get-VBRRestGUI

#Get-VBRRestHelp -r $rest -search "configBackup/backup"
Invoke-VBRRestMethod -r $rest -path "/api/v1/configBackup/backup" -method post