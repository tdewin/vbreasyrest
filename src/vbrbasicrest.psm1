function Set-InsecureSSL {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $code= @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
        Add-Type -TypeDefinition $code -Language CSharp
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}
function Get-VBRRestConnection {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)]$uri,
        [Parameter(Mandatory=$true)]$login,
        [Parameter(Mandatory=$true)]$password,
        [switch]$insecure=$false
        )

    $iparams = @{
        "method"="get";
        "uri"= ("{0}/swagger/v1.1-rev0/swagger.json" -f $uri);
    }
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $insecure) {
        $iparams.SkipCertificateCheck = $insecure
    }
    $help = Invoke-RestMethod @iparams

    $iparams = @{
        "method"="post";
        "headers"=@{"x-api-version"="1.1-rev0"};
        "uri"= ("$uri/api/oauth2/token");
        "body"=@{"grant_type"="password";username=$login;password=$password};
    }
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $insecure) {
        $iparams.SkipCertificateCheck = $insecure
    }
    $answer = Invoke-RestMethod @iparams
    Write-Verbose $answer.'.expires'
    $token =  "Bearer {0}" -f $answer.access_token
    $exp = $answer.'.expires'
    if ($exp.gettype() -ne [System.DateTime]) {
        $exp = [System.DateTime]::Parse($exp)
    }
    
    $autorenew = $exp.AddSeconds(-($answer.expires_in)/2)
    if($insecure) {
        Set-InsecureSSL
    }
    return @{uri=$uri;exp=$exp;autorenew=$autorenew;insecure=$insecure;headers=@{"x-api-version"="1.1-rev0";"Authorization"=$token};orig=$answer;help=$help}
}
function Update-VBRRestConnection {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection)


    $iparams = @{
        "method"="post";
        "headers"=@{"x-api-version"="1.1-rev0"};
        "uri"= ("{0}/api/oauth2/token" -f $restconnection.uri);
        "body"=@{"grant_type"="refresh_token";refresh_token=$restconnection.orig.refresh_token};
    }
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $restconnection.insecure) {
        $iparams.SkipCertificateCheck = $restconnection.insecure
    }   

    $answer = Invoke-RestMethod @iparams
    $token =  "Bearer {0}" -f $answer.access_token

    $restconnection.orig=$answer
    $restconnection.headers = @{"x-api-version"="1.1-rev0";"Authorization"=$token}
    $exp = $answer.'.expires'
    if ($exp.gettype() -ne [System.DateTime]) {
        $exp = [System.DateTime]::Parse($exp)
    }
    $restconnection.exp = $exp
    $restconnection.autorenew = $restconnection.exp.AddSeconds(-($answer.expires_in)/2)
}
function Invoke-VBRRestMethod {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $path,$method="get",$body=$null)

    $exp = $restconnection.exp
    if(($exp - (get-date)).totalseconds -gt 1) 
    {
        $answer = $null
        $headers = $restconnection.headers
        $uri = ("{0}/{1}" -f $restconnection.uri,$path)

        if (($restconnection.autorenew - (get-date)).TotalSeconds -lt 0) {
            Write-Verbose "Autorenewing"
            Update-VBRRestConnection -restconnection $restconnection
        }

        $iparams = @{"Method"=$method;"Headers"=$headers;"Uri"=$uri;ContentType="application/json"}
        if ($body) {
            $iparams.Body = ($body | ConvertTo-Json -Compress -Depth 100)
        } 
        
        if ($PSVersionTable.PSVersion.Major -ge 7 -and $restconnection.insecure) {
            $iparams.SkipCertificateCheck = $restconnection.insecure
        }

        Write-Verbose ($iparams | ConvertTo-Json -Depth 3)
        $answer = Invoke-RestMethod @iparams
        return $answer
    } else {
        throw "Expired session $exp, too late for autorenew"
    }
}


function New-VBRRestConfigFile {
    $vbrrestconfigfile = join-path -path  $env:USERPROFILE -childpath ".vbrrestconfig"

    $config = @{
        "servers"=@("https://127.0.0.1")
        "login"="domain\administrator"
   }

    $config | ConvertTo-Json | set-content $vbrrestconfigfile
    try {start-process -FilePath notepad -ArgumentList $vbrrestconfigfile -ErrorAction Ignore} catch {write-host "File located under $vbrrestconfigfile"}
}

function Get-VBRRestGUI {
    [CmdletBinding()] 
    param(
        $server="",
        $port="9419",
        $login="",
        [switch]$insecure=$false
    )

    $rest = @{"status"="failed"}
 [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="700"
        Height="250"
        Title="Login">
     <Grid Margin="0,0,0,0">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="3*"/>
            <ColumnDefinition Width="4*"/>
            <ColumnDefinition Width="1*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="4*"/>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="3*"/>
            <RowDefinition Height="2*"/>
        </Grid.RowDefinitions>

        <Border  Grid.Row="0" Grid.RowSpan="6" Grid.Column ="0" Grid.ColumnSpan="3"  Background="#005f4b"/>

        <TextBlock Margin="5,5,0,0" Grid.ColumnSpan="2"  Grid.Column="0" Grid.Row="0" Foreground="White" FontSize="32" Text="VBR Easy Rest" />

        <TextBlock Margin="5,5,0,0" VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="1" Foreground="White" FontSize="16" Text="Server" />
        <TextBlock Margin="5,5,0,0" VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="2" Foreground="White" FontSize="16" Text="Login"/>
        <TextBlock Margin="5,5,0,0" VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="3" Foreground="White" FontSize="16" Text="Password"/>
        <CheckBox Margin="5,5,0,5"  VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="4" x:Name="iunsecure" Foreground="White" FontSize="16" Content="Ignore Self Signed"/>
        <TextBlock x:Name="ostatus" Margin="5,5,0,0" Grid.ColumnSpan="2"  VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="5" Foreground="White" FontSize="16" Text="" />


        <ComboBox x:Name="iserver" FontSize="14"    Grid.Column="1" Grid.Row="1" IsEditable="True" Margin="0,5,5,0" HorizontalAlignment="Stretch" VerticalContentAlignment="Center">
        </ComboBox>


        <TextBox x:Name="iport"  FontSize="14"  Grid.Column="2" Grid.Row="1"   Text="9419" Margin="0,5,5,0" HorizontalAlignment="Stretch" VerticalContentAlignment="Center"/>
        <TextBox x:Name="ilogin"  FontSize="14"    Grid.Column="1" Grid.Row="2" Grid.ColumnSpan="2"  Margin="0,5,5,0" Text="administrator"  HorizontalAlignment="Stretch" VerticalContentAlignment="Center"/>
        <PasswordBox x:Name="ipassword" FontSize="14"  Grid.Column="1" Grid.Row="3" Grid.ColumnSpan="2" Margin="0,5,5,0"  HorizontalAlignment="Stretch" VerticalContentAlignment="Center"/>
                        
        <StackPanel Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="2" Orientation="Horizontal"
            HorizontalAlignment="Right" VerticalAlignment="Bottom">
              <Button x:Name="bcancel" Content="Cancel"
                    ClickMode="Press"
                    FontSize="16"
                    Margin="0,0,5,5" Width="150" Foreground="#005f4b" Background="White"  />
              <Button x:Name="blogin" Content="Login"
                      ClickMode="Press"
                      FontSize="16"
                      Margin="0,0,5,5" Width="150" Foreground="#005f4b" Background="White"  />
        </StackPanel>
    </Grid>
</Window>
"@ 
 
    if (@($([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.location -match "PresentationFramework"})).count -lt 1) {
        [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    }
    
    try{
       $Form=[Windows.Markup.XamlReader]::Load( (New-Object System.Xml.XmlNodeReader $XAML) )
       $istatus = $Form.FindName("ostatus")
       $iserver = $Form.FindName("iserver")
       $iport = $Form.FindName("iport")
       $ilogin = $Form.FindName("ilogin")
       $iunsecure = $Form.FindName("iunsecure")

       $vbrrestconfigfile = join-path -path  $env:USERPROFILE -childpath ".vbrrestconfig"

       $config = @{
            "servers"=@("https://127.0.0.1")
            "login"="administrator"
       }

       if (test-path $vbrrestconfigfile) {
            $config = Get-Content -Path $vbrrestconfigfile | convertfrom-json
       }

       foreach ($s in @($config.servers)) {
            $ci = [System.Windows.Controls.ComboBoxItem]::new()
            $ci.content = $s
            $iserver.items.add($ci) | out-null
            $iserver.text = $s
       }

       if ($server -ne "") {
            $ci = [System.Windows.Controls.ComboBoxItem]::new()
            $ci.content = $server
            $iserver.items.insert(0,$ci) | out-null
            $iserver.text = $server    
       }

       if ($login -eq "") {
            $login = $config.login
       }

       $iport.text = $port
       $ilogin.text = $login
       $iunsecure.IsChecked = $insecure

       $loginClick = {        
            $rest.status = "trylogin"

            $server = $iserver.text
            $port = $iport.text
            $uri = ("{0}:{1}" -f $server,$port)

           

            $login = $ilogin.text
            $password = $Form.FindName("ipassword").Password
            $insecure = $iunsecure.IsChecked

            if ($login -ne "" -and $password -ne "" -and $server -ne "") {
                write-verbose "Connecting to $uri with $login (self sign:$insecure)"

                if ($insecure) {
                    Set-InsecureSSL
                }

                
                try {
                    $restcopy = Get-VBRRestConnection -uri $uri -login $login -password $password -insecure:$insecure
                    foreach($restm in $restcopy.keys) {
                        $rest."$restm" = $restcopy."$restm"
                    }
                    $rest.status = "logindone"
                    $Form.Close() | out-null
                } catch {
                    $istatus.text = "Failed: $_"
                    Write-Verbose "Error $_"
                }
            } else {
                $istatus.text = "Empty field detected"
            }
            
            
       }

       

       $cancelclick = {
            $Form.Close() | out-null
       }
       $Form.FindName("blogin").add_click($loginClick)  | out-null
       $Form.FindName("bcancel").add_click($cancelclick)  | out-null
       $Form.ShowDialog()  | out-null

    } catch {
        $rest.status = "Failed: $_"
        $Form.Close()  | out-null
    } finally {
       if (-not $Form.Closed) {
            $Form.Close()  | out-null
       }     
    }

    return $rest
}

function Get-VBRRestHelpPath {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $path=$null
    )

    $help = $restconnection.help

    $pmatches = @($help.paths | get-member -Type noteproperty | Where-Object { $_.name -ieq $path})
    if ($pmatches.Count -eq 1) {
        $pmatch = $pmatches[0]
        $mname = $pmatch.name
        write-host "$mname"
        $mobj = $help.paths."$mname"

        write-host ("API Path: $mname`n`n")

        foreach($method in ($mobj | Get-Member -Type NoteProperty | ForEach-Object {$_.name})) {
            $ep = $mobj."$method"
            write-host ("{0}: {1}" -f $method,$ep.description)
            if($ep.requestBody.required) {
                write-host " Requires Data:"
                write-host ('  Invoke-VBRRestMethod -r $rest -path "{0}" -method {1} -body $data' -f $mname,$method)
            } else {
                write-host ('  Invoke-VBRRestMethod -r $rest -path "{0}" -method {1}' -f $mname,$method)
            }
            write-host ("https://helpcenter.veeam.com/docs/backup/vbr_rest/reference/vbr-rest-v1-1-rev0.html?ver=120#tag/{0}/operation/{1} `n`n" -f ($ep.tags[0] -replace "[ ]","-"),$ep.operationId)
        }
    } else {
        write-verbose "could not find exact path $path"
    }

}



function Get-VBRRestHelp {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $search=$null,
        $path=$null
    )
    $help = $restconnection.help

    if ($search) {
        $pmatches = @($help.paths | get-member -Type noteproperty | Where-Object { $_.name -imatch $search})
        if ($pmatches.Count -eq 0) {
            write-host "No Match"
        } elseif($pmatches.Count -gt 1) {
            foreach($pmatch in $pmatches) {
                write-host $pmatch.name
            }
        } else {
            Get-VBRRestHelpPath -restconnection $restconnection -path $pmatches[0].name
        }
    } elseif ($path) {
        Get-VBRRestHelpPath -restconnection $restconnection -path $path
    } else {
        $pmatches = @($help.paths | get-member -Type noteproperty)
        foreach($pmatch in $pmatches) {
            write-host $pmatch.name
        }
    }
}

function Wait-VBRRestAutomationSession {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $session
    )

    while ($($session = Invoke-VBRRestMethod -r $tgt -path ("/api/v1/automation/sessions/{0}" -f $session.id)  -method get; $session.state) -ne "stopped") {
        Start-Sleep -Milliseconds 1000
        Write-Progress -Activity $session.name -Status $session.state -PercentComplete $session.progressPercent
    }

    return $session
}

function Get-VBRRestAutomationSessionLog {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $session
    )

    return $(Invoke-VBRRestMethod -r $restconnection -path ("/api/v1/automation/sessions/{0}/logs" -f $session.id) -method get)
}

Export-ModuleMember -Function New-VBRRestConfigFile
Export-ModuleMember -Function Get-VBRRestGUI
Export-ModuleMember -Function Get-VBRRestHelp
Export-ModuleMember -Function Set-InsecureSSL
Export-ModuleMember -Function Invoke-VBRRestMethod
Export-ModuleMember -Function Update-VBRRestConnection
Export-ModuleMember -Function Get-VBRRestConnection
Export-ModuleMember -Function Wait-VBRRestAutomationSession
Export-ModuleMember -Function Get-VBRRestAutomationSessionLog