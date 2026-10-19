# Parallel, bounded native processes. No installs, admin rights or uploads.
$ErrorActionPreference = 'Continue'
$reportText = New-Object System.Text.StringBuilder
function Save-LayeroLine($value) {
  $text = ($value | Out-String) -replace '(?im)(Uses proxy env variable .* == ).*','$1[redacted]' -replace '(?im)(Proxy-Authorization:|Authorization:|Set-Cookie:).*','$1 [redacted]'
  [void]$reportText.AppendLine($text)
}
function Start-LayeroProbe($exe, $arguments, $targetHost, $kind) {
  $command = Get-Command $exe -ErrorAction SilentlyContinue
  if (-not $command) { Save-LayeroLine "$targetHost $kind unavailable: $exe"; return }
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = $command.Source; $info.Arguments = $arguments
  $info.UseShellExecute = $false; $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $info
  try {
    [void]$process.Start()
    [pscustomobject]@{ Process=$process; Out=$process.StandardOutput.ReadToEndAsync(); Err=$process.StandardError.ReadToEndAsync(); HostName=$targetHost; Kind=$kind }
  } catch { Save-LayeroLine "$targetHost $kind failed to start: $_"; $process.Dispose() }
}
function Finish-LayeroProbes($probes, $budgetMs) {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  foreach ($probe in $probes) {
    $remaining = [Math]::Max(0, $budgetMs - [int]$clock.ElapsedMilliseconds)
    $limited = -not $probe.Process.WaitForExit($remaining)
    if ($limited) { try { $probe.Process.Kill() } catch {} }
    $exited = $probe.Process.WaitForExit(1000)
    $outText = if ($probe.Out.IsCompleted -and -not $probe.Out.IsFaulted) { $probe.Out.Result } else { '[stdout incomplete]' }
    $errText = if ($probe.Err.IsCompleted -and -not $probe.Err.IsFaulted) { $probe.Err.Result } else { '[stderr incomplete]' }
    $result = $outText + "`n" + $errText
    Save-LayeroLine ("===== " + $probe.HostName + ' ' + $probe.Kind + ' =====')
    Save-LayeroLine $result
    $exitCode = if ($exited) { $probe.Process.ExitCode } else { 'unknown; process did not terminate' }
    Save-LayeroLine ("exit=" + $exitCode + " time_limited=$limited")
    if ($probe.Kind -eq 'HTTPS') {
      $destination = $probe.HostName
      if ($result -match '(?m)^LAYERO_REMOTE_IP=([0-9a-fA-F:.]+)') { $destination = $Matches[1] }
      if ($result -match '(?i)proxy|CONNECT tunnel') {
        $destination = $probe.HostName
        Save-LayeroLine 'Proxy detected: tracing hostname separately, not the proxy/browser path.'
      }
      $script:routeTargets[$probe.HostName] = $destination
    }
    $probe.Process.Dispose()
  }
}
Write-Host 'Layero: checking connection...'
Save-LayeroLine ('Layero network diagnostics 1.1; UTC: ' + [DateTime]::UtcNow.ToString('o'))
Save-LayeroLine 'Parallel quick snapshot. System DNS/proxy can differ from browser. ICMP routes have a 4s budget: partial outbound hops, NOT TCP443, TLS, packet-loss statistics or the return path. No uploads.'
$script:routeTargets = @{}
$probes = @()
$probes += Start-LayeroProbe 'curl.exe' '-q -sS --connect-timeout 3 --max-time 4 https://network-check.layero.app/__layero/network-info' 'network-check.layero.app' 'Network'
foreach ($target in @('https://app.layero.ru/login','https://api.layero.ru/health','https://status.layero.app/','https://docs.layero.ru/','https://layero.ru/')) {
  $targetHost = ([uri]$target).DnsSafeHost
  $script:routeTargets[$targetHost] = $targetHost
  $probes += Start-LayeroProbe 'nslookup.exe' "-timeout=1 -retry=1 -type=A $targetHost" $targetHost 'DNS A'
  $probes += Start-LayeroProbe 'nslookup.exe' "-timeout=1 -retry=1 -type=AAAA $targetHost" $targetHost 'DNS AAAA'
  $format = '\nLAYERO_REMOTE_IP=%{remote_ip}\nHTTP=%{http_code} DNS=%{time_namelookup} CONNECT=%{time_connect} TLS=%{time_appconnect} FIRST_BYTE=%{time_starttransfer} TOTAL=%{time_total}\n'
  $probes += Start-LayeroProbe 'curl.exe' "-q -v --connect-timeout 3 --max-time 6 --output NUL --write-out `"$format`" $target" $targetHost 'HTTPS'
}
Finish-LayeroProbes @($probes | Where-Object { $_ }) 7000
$routes = @()
foreach ($targetHost in $script:routeTargets.Keys) {
  $destination = $script:routeTargets[$targetHost]
  $routes += Start-LayeroProbe 'tracert.exe' "-d -h 16 -w 250 $destination" $targetHost 'ICMP route'
}
Finish-LayeroProbes @($routes | Where-Object { $_ }) 4000
Save-LayeroLine ('Finished UTC: ' + [DateTime]::UtcNow.ToString('o'))
Write-Host 'Done. Copy the text between BEGIN and END and send it to support.'
Write-Output "`n--- BEGIN LAYERO REPORT ---"
Write-Output $reportText.ToString()
Write-Output '--- END LAYERO REPORT ---'
