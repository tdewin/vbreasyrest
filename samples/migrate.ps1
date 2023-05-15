import-module .\vbrbasicrest.psm1

$user = "vbr\administrator"
$port = 9419
$src = Get-VBRRestGUI -server https://192.168.0.92 -port $port -login $user  -insecure -Verbose
$tgt = Get-VBRRestGUI -server https://192.168.0.191 -port $port -login $user -insecure -Verbose

#Get-VBRRestHelp -r $src -search export
#Get-VBRRestHelp -r $src -search import


#Get-VBRRestHelp -r $src -search "/api/v1/automation/credentials/export"
$credentials = Invoke-VBRRestMethod -r $src -path "/api/v1/automation/credentials/export" -method post

#change passwords after import in gui and give fake password if you dont want to post passwords over rest, but password can not be empty!
foreach($cred in $credentials.credentials) {
    #GOD I HATE PS =)
    write-host ("Input password for {0} description {1}" -f $cred.username,$cred.description)
    $cred.password = [System.Management.Automation.PSCredential]::new("x",$(read-host -Prompt ("Password {0}" -f $cred.username) -AsSecureString)).getNetworkCredential().Password
}

#Get-VBRRestHelp -r $src -search "/api/v1/automation/credentials/import"
$session = Invoke-VBRRestMethod -r $tgt -path "/api/v1/automation/credentials/import" -method post -body $credentials
$session = Wait-VBRRestAutomationSession -r $tgt -session $session
write-host $session.result

#Get-VBRRestHelp -r $src -search "/api/v1/automation/managedServers/export"
$managedServers = Invoke-VBRRestMethod -r $src -path "/api/v1/automation/managedServers/export" -method post
#hardened repo filtering
$managedServers.linuxHosts = @($managedServers.linuxHosts | Where-Object { $_ -ne $null })

#Get-VBRRestHelp -r $src -search "/api/v1/automation/managedServers/import"
$session = Invoke-VBRRestMethod -r $tgt -path "/api/v1/automation/managedServers/import" -method post -body $managedServers
$session = Wait-VBRRestAutomationSession -r $tgt -session $session
write-host $session.result


$repos = Invoke-VBRRestMethod -r $src -path "/api/v1/automation/repositories/export" -method post
<# only if you are feeling lucky; remapping all to a single default repo at target
$session = Invoke-VBRRestMethod -r $tgt -path "/api/v1/automation/repositories/import" -method post -body $repos
$session = Wait-VBRRestAutomationSession -r $tgt -session $session
write-host $session.result
(Get-VBRRestAutomationSessionLog -restconnection $tgt -session $session).records
#>
$tgtrepos = Invoke-VBRRestMethod -r $tgt -path "/api/v1/automation/repositories/export" -method post
$defaultrepo = $tgtrepos.WindowsLocalRepositories[0]

#Get-VBRRestHelp -r $src -search "/api/v1/automation/jobs/export"
$jobs = Invoke-VBRRestMethod -r $src -path "/api/v1/automation/jobs/export" -method post

#remapping to default repo on tgt
foreach($job in $jobs.jobs) {
    $job.storage.backupRepository.name = $defaultrepo.name
    $job.storage.backupRepository.tag = $defaultrepo.tag
}

#Get-VBRRestHelp -r $src -search "/api/v1/automation/jobs/import"
$session = Invoke-VBRRestMethod -r $tgt -path "/api/v1/automation/jobs/import" -method post -body $jobs
$session = Wait-VBRRestAutomationSession -r $tgt -session $session
write-host $session.result
(Get-VBRRestAutomationSessionLog -restconnection $tgt -session $session).records
