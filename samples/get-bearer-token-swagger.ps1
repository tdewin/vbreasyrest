import-module .\vbrbasicrest.psm1


$server = "https://127.0.0.1"
$port = 9419

$rest = (Get-VBRRestGUI -server $server -port $port -login $user  -insecure -Verbose)
$rest.headers.authorization | Set-Clipboard
#start swagger browser
start-process "$($rest.uri)/swagger"

