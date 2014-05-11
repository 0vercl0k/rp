# benchmark.psm1
# Exports: Benchmark-Command

function Benchmark-Command ([ScriptBlock]$Expression, [int]$Samples = 1, [Switch]$Silent, [Switch]$Long) {
<#
.SYNOPSIS
  Runs the given script block and returns the execution duration.
  Hat tip to StackOverflow. http://stackoverflow.com/questions/3513650/timing-a-commands-execution-in-powershell
  
.EXAMPLE
  Benchmark-Command { ping -n 1 google.com }
#>
  $timings = @()
  do {
    $sw = New-Object Diagnostics.Stopwatch
    if ($Silent) {
      $sw.Start()
      $null = & $Expression
      $sw.Stop()
      Write-Host "." -NoNewLine
    }
    else {
      $sw.Start()
      & $Expression
      $sw.Stop()
    }
    $timings += $sw.Elapsed
    
    $Samples--
  }
  while ($Samples -gt 0)
  
  Write-Host
  
  $stats = $timings | Measure-Object -Average -Minimum -Maximum -Property Ticks
  
  # Print the full timespan if the $Long switch was given.
  if ($Long) {  
    Write-Host "Avg: $((New-Object System.TimeSpan $stats.Average).ToString())"
    Write-Host "Min: $((New-Object System.TimeSpan $stats.Minimum).ToString())"
    Write-Host "Max: $((New-Object System.TimeSpan $stats.Maximum).ToString())"
  }
  else {
    # Otherwise just print the milliseconds which is easier to read.
    Write-Host "Avg: $((New-Object System.TimeSpan $stats.Average).TotalMilliseconds)ms"
    Write-Host "Min: $((New-Object System.TimeSpan $stats.Minimum).TotalMilliseconds)ms"
    Write-Host "Max: $((New-Object System.TimeSpan $stats.Maximum).TotalMilliseconds)ms"
  }
}

Export-ModuleMember Benchmark-Command