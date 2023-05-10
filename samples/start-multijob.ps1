Import-Module .\vbrbasicrest.psm1
$rest = Get-VBRRestGUI

#get-vbrresthelp -r $rest -search "jobs/states"
$jobs = Invoke-VBRRestMethod -r $rest -path "/api/v1/jobs/states" -method get
$selectedJobs = $jobs.data | select id,name,status,lastResult,nextRun | out-gridview  -OutputMode Multiple
foreach($selectedJob in $selectedJobs) {
	#get-vbrresthelp -r $rest -search "start"
	Invoke-VBRRestMethod -r $rest -path ("/api/v1/jobs/{0}/start" -f $selectedJob.id) -method post
}
