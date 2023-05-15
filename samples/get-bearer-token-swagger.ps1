import-module .\vbrbasicrest.psm1


$server = "https://192.168.0.92"
$port = 9419

$rest = (Get-VBRRestGUI -server $server -port $port -login $user  -insecure -Verbose)
$rest.headers.authorization | Set-Clipboard
start-process "$($rest.uri)/swagger"

