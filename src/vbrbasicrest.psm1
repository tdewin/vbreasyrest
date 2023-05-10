function Set-InsecureSSL {
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
function Get-VBRRestConnection {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)]$uri,
        [Parameter(Mandatory=$true)]$login,
        [Parameter(Mandatory=$true)]$password)
    $help = Invoke-RestMethod -Method get -Uri ("{0}/swagger/v1.1-rev0/swagger.json" -f $uri)
    $answer = Invoke-RestMethod -Method post -Headers @{"x-api-version"="1.1-rev0"} -Uri ("$uri/api/oauth2/token") -Body @{"grant_type"="password";username=$login;password=$password}
    $token =  "Bearer {0}" -f $answer.access_token
    $exp = [System.DateTime]::Parse($answer.'.expires')
    $autorenew = $exp.AddSeconds(-($answer.expires_in)/2)
    return @{uri=$uri;exp=$exp;autorenew=$autorenew;headers=@{"x-api-version"="1.1-rev0";"Authorization"=$token};orig=$answer;help=$help}
}
function Update-VBRRestConnection {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection)
    $answer = Invoke-RestMethod -Method post -Headers @{"x-api-version"="1.1-rev0"} -Uri ("{0}/api/oauth2/token" -f $restconnection.uri) -Body @{"grant_type"="refresh_token";refresh_token=$restconnection.orig.refresh_token}
    $token =  "Bearer {0}" -f $answer.access_token


    $restconnection.orig=$answer
    $restconnection.headers = @{"x-api-version"="1.1-rev0";"Authorization"=$token}
    $restconnection.exp = [System.DateTime]::Parse($answer.'.expires')
    $restconnection.autorenew = $restconnection.exp.AddSeconds(-($answer.expires_in)/2)
}
function Invoke-VBRRestMethod {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $path,$method="get",$body=$null)

    $answer = $null
    $headers = $restconnection.headers
    $uri = ("{0}/{1}" -f $restconnection.uri,$path)

    if (($rest.autorenew - (get-date)).TotalSeconds -lt 0) {
        Write-Verbose "Autorenewing"
        Update-VBRRestConnection -restconnection $rest
    }

    if ($body -ne $null) {
        $answer = Invoke-RestMethod -Method $method -Headers $headers -Uri $uri
    } else {
        $answer = Invoke-RestMethod -Method $method -Headers $headers -body $body -Uri $uri
    }
    return $answer
}
function Get-VBRRestGUI {
    $rest = @{"status"="failed"}

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="500"
        Height="200"
        Title="Login">
     <Grid Margin="0,0,0,0">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="3*"/>
            <ColumnDefinition Width="5*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="2*"/>
            <RowDefinition Height="3*"/>
        </Grid.RowDefinitions>

        <Border  Grid.Row="0" Grid.RowSpan="4" Grid.Column ="0" Grid.ColumnSpan="2"  Background="#005f4b"/>

        <TextBlock Margin="5,5,0,0" VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="0" Foreground="White" FontSize="16" Text="Server" />
        <TextBlock Margin="5,5,0,0" VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="1" Foreground="White" FontSize="16" Text="Login"/>
        <TextBlock Margin="5,5,0,0" VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="2" Foreground="White" FontSize="16" Text="Password"/>
        <CheckBox Margin="5,5,0,5"  VerticalAlignment="Bottom" Grid.Column="0" Grid.Row="3" x:Name="iunsecure" Foreground="White" FontSize="16" Content="Ignore Self Signed"/>

        <TextBox x:Name="iserver"   Grid.Column="1" Grid.Row="0" Margin="0,5,5,0" Text="https://localhost:9419"  HorizontalAlignment="Stretch" VerticalContentAlignment="Center"/>
        <TextBox x:Name="ilogin"    Grid.Column="1" Grid.Row="1" Margin="0,5,5,0" Text="administrator"  HorizontalAlignment="Stretch" VerticalContentAlignment="Center"/>
        <PasswordBox x:Name="ipassword" Grid.Column="1" Grid.Row="2" Margin="0,5,5,0"  HorizontalAlignment="Stretch" VerticalContentAlignment="Center"/>
                        
        <StackPanel Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="1" Orientation="Horizontal"
            HorizontalAlignment="Right" VerticalAlignment="Bottom">
              <Button x:Name="blogin" Content="Login"
                      ClickMode="Press"
                      FontSize="18"
                      Margin="0,0,5,5" Width="150" Foreground="#005f4b" Background="White"  />
        </StackPanel>
    </Grid>
</Window>
"@ 
    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    try{
       $Form=[Windows.Markup.XamlReader]::Load( (New-Object System.Xml.XmlNodeReader $XAML) )

       $loginclick = {
            $rest.status = "trylogin"

            $uri = $Form.FindName("iserver").text
            $login = $Form.FindName("ilogin").text
            $password = $Form.FindName("ipassword").Password
            $insecure = $Form.FindName("iunsecure").IsChecked

            if ($insecure) {
                Set-InsecureSSL
            }

            $restcopy = Get-VBRRestConnection -uri $uri -login $login -password $password
            foreach($restm in $restcopy.keys) {
                $rest."$restm" = $restcopy."$restm"
            }
            
            $rest.status = "logindone"

            $Form.Close() | out-null
       }
       $Form.FindName("blogin").add_click($loginclick)  | out-null
       $Form.ShowDialog()  | out-null

    } catch {
       Write-Error "Could not load Xaml $error"
       $rest.status = "loginfailed"
    } finally {
       if (-not $Form.Closed) {
            $Form.Close()  | out-null
       }     
    }
    return $rest
}
function Get-VBRRestHelp {
    [CmdletBinding()] 
    param(
        [Parameter(Mandatory=$true)][Alias("r")]$restconnection,
        $search=$null,
        $path=$null
    )
    $help = $rest.help

    if ($search) {
        $matches = @($help.paths | get-member -Type noteproperty | ? { $_.name -imatch $search})
        if ($matches.Count -eq 0) {
            write-host "No Match"
        } elseif($matches.Count -gt 1) {
            foreach($match in $matches) {
                write-host $match.name
            }
        } else {
            $match = $matches[0]

            $mname = $match.name
            $mobj = $help.paths."$mname"

            write-host ("$mname`n###############################")

            foreach($method in ($mobj | gm -Type NoteProperty | % {$_.name})) {
                $ep = $mobj."$method"
                write-host ("{0}: {1}" -f $method,$ep.description)
                write-host ("https://helpcenter.veeam.com/docs/backup/vbr_rest/reference/vbr-rest-v1-1-rev0.html?ver=120#tag/{0}/operation/{1} `n" -f ($ep.tags[0] -replace "[ ]","-"),$ep.operationId)
            }

        }
    } else {
        return $rest.help
    }
}
