# TEMPORARY (#454): Windows upgrade test for the publisher rename.
# Remove before merging.
#
# Installs 0.29.0 (publisher "clavixlabs"), then upgrades to a 0.29.1 build
# with publisher "clavix", through the installer's GUI the way a user would:
# every dialog is driven by posting IDOK (Next / Install / Uninstall /
# Finish / OK) to it once its default button is enabled.
param(
  [Parameter(Mandatory)] [string] $Old,
  [Parameter(Mandatory)] [string] $New
)
$ErrorActionPreference = 'Stop'

Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class Win {
  delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] static extern IntPtr GetDlgItem(IntPtr h, int id);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);

  public static string Text(IntPtr h) {
    var s = new StringBuilder(1024); GetWindowText(h, s, s.Capacity); return s.ToString();
  }

  public static List<IntPtr> TopLevel(HashSet<uint> pids) {
    var r = new List<IntPtr>();
    EnumWindows((h, l) => {
      uint pid; GetWindowThreadProcessId(h, out pid);
      if (pids.Contains(pid) && IsWindowVisible(h)) r.Add(h);
      return true;
    }, IntPtr.Zero);
    return r;
  }

  public static string Describe(IntPtr h) {
    var parts = new List<string> { Text(h) };
    EnumChildWindows(h, (c, l) => {
      if (IsWindowVisible(c)) { var t = Text(c); if (t.Length > 0) parts.Add(t); }
      return true;
    }, IntPtr.Zero);
    return string.Join(" | ", parts);
  }

  // Posts IDOK when the dialog's default button exists and is enabled.
  public static bool PressDefault(IntPtr h) {
    var b = GetDlgItem(h, 1);
    if (b == IntPtr.Zero || !IsWindowEnabled(b) || !IsWindowVisible(b)) return false;
    return PostMessage(h, 0x0111, (IntPtr)1, b);
  }
}
'@

$UninstKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\clavix'
$NewKey = 'HKCU:\Software\clavix\clavix'
$LegacyKey = 'HKCU:\Software\clavixlabs\clavix'
$DefaultDir = Join-Path $env:LOCALAPPDATA 'clavix'
$CustomDir = 'C:\ClavixCustom'

function Stop-Clavix {
  Get-Process clavix -ErrorAction SilentlyContinue | Stop-Process -Force
}

function Get-RegDefault($key) {
  if (Test-Path $key) { (Get-Item $key).GetValue('') } else { $null }
}

function Reset-Install {
  Stop-Clavix
  if (Test-Path $UninstKey) {
    $loc = (Get-ItemProperty $UninstKey).InstallLocation.Trim('"')
    $un = Join-Path $loc 'uninstall.exe'
    if (Test-Path $un) {
      # _?= keeps the uninstaller in place so -Wait really waits.
      Start-Process $un -ArgumentList '/S', "_?=$loc" -Wait
    }
  }
  foreach ($k in $UninstKey, 'HKCU:\Software\clavix', 'HKCU:\Software\clavixlabs') {
    if (Test-Path $k) { Remove-Item $k -Recurse -Force }
  }
  foreach ($d in $DefaultDir, $CustomDir) {
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
  }
}

function Install-Old($dir) {
  $setup = Join-Path $Old 'clavix_0.29.0_x64-setup.exe'
  $argv = @('/S')
  if ($dir) { $argv += "/D=$dir" }
  Start-Process $setup -ArgumentList $argv -Wait
  if (-not (Test-Path $UninstKey)) { throw '0.29.0 did not install' }
}

# Runs an installer through its GUI. Returns the exit code, every distinct
# dialog seen, and the error dialogs.
function Invoke-Gui($setup) {
  $p = Start-Process $setup -PassThru
  $null = $p.Handle  # keeps ExitCode readable after exit
  $seen = [System.Collections.Generic.List[string]]::new()
  $errors = [System.Collections.Generic.List[string]]::new()
  $deadline = (Get-Date).AddMinutes(4)
  while (-not $p.HasExited) {
    if ((Get-Date) -gt $deadline) { $errors.Add('TIMEOUT'); break }
    $pids = [System.Collections.Generic.HashSet[uint32]]::new()
    $null = $pids.Add([uint32]$p.Id)
    Get-Process | Where-Object { $_.ProcessName -match '^(uninstall|Un_.*|Au_.*)$' } |
      ForEach-Object { $null = $pids.Add([uint32]$_.Id) }
    foreach ($h in [Win]::TopLevel($pids)) {
      $d = [Win]::Describe($h)
      if (-not $seen.Contains($d)) { $seen.Add($d) }
      if ($d -match '(?i)unable|error|failed|is running') {
        if (-not $errors.Contains($d)) { $errors.Add($d) }
      }
      if ([Win]::PressDefault($h)) { Start-Sleep -Milliseconds 1500; break }
    }
    if ($errors.Count -gt 0) { Start-Sleep -Seconds 2; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
  Get-Process | Where-Object { $_.ProcessName -match '^(uninstall|Un_.*|Au_.*)$' } | Stop-Process -Force -ErrorAction SilentlyContinue
  Stop-Clavix
  [pscustomobject]@{ Exit = $p.ExitCode; Seen = $seen; Errors = $errors }
}

function Get-State {
  $u = if (Test-Path $UninstKey) { Get-ItemProperty $UninstKey } else { $null }
  $ver = { param($d) $e = Join-Path $d 'clavix.exe'; if (Test-Path $e) { (Get-Item $e).VersionInfo.ProductVersion } else { '-' } }
  [pscustomobject]@{
    DisplayVersion  = if ($u) { $u.DisplayVersion } else { '-' }
    Publisher       = if ($u) { $u.Publisher } else { '-' }
    InstallLocation = if ($u) { $u.InstallLocation.Trim('"') } else { '-' }
    NewKey          = Get-RegDefault $NewKey
    LegacyKey       = Get-RegDefault $LegacyKey
    DefaultExe      = & $ver $DefaultDir
    CustomExe       = & $ver $CustomDir
  }
}

$results = @()
foreach ($variant in 'nohook', 'hook') {
  foreach ($case in @(
      @{ Name = 'default dir, GUI'; Dir = $null; Gui = $true },
      @{ Name = 'custom dir, GUI'; Dir = $CustomDir; Gui = $true },
      @{ Name = 'custom dir, silent'; Dir = $CustomDir; Gui = $false })) {
    $setup = Join-Path $New "$variant-setup.exe"
    $title = "$variant / $($case.Name)"
    Write-Host "::group::$title"
    Reset-Install
    Install-Old $case.Dir
    Write-Host 'After 0.29.0:'; Get-State | Format-List | Out-String | Write-Host
    if ($case.Gui) {
      $run = Invoke-Gui $setup
    } else {
      $p = Start-Process $setup -ArgumentList '/S' -Wait -PassThru
      $run = [pscustomobject]@{ Exit = $p.ExitCode; Seen = @(); Errors = @() }
    }
    Write-Host 'Dialogs:'; $run.Seen | ForEach-Object { Write-Host "  $_" }
    $s = Get-State
    Write-Host 'After 0.29.1:'; $s | Format-List | Out-String | Write-Host
    $expected = if ($case.Dir) { $case.Dir } else { $DefaultDir }
    $other = if ($case.Dir) { $s.DefaultExe } else { $s.CustomExe }
    $here = if ($case.Dir) { $s.CustomExe } else { $s.DefaultExe }
    $ok = ($run.Errors.Count -eq 0) -and ($run.Exit -eq 0) -and
      ($s.DisplayVersion -eq '0.29.1') -and ($s.Publisher -eq 'clavix') -and
      ($s.InstallLocation -eq $expected) -and ($here -eq '0.29.1') -and ($other -eq '-') -and
      ($s.NewKey -eq $expected) -and ($null -eq $s.LegacyKey)
    $results += [pscustomobject]@{
      Variant = $variant; Case = $case.Name; Pass = $ok; Exit = $run.Exit
      Errors = ($run.Errors -join ' // '); Version = $s.DisplayVersion
      Location = $s.InstallLocation; DefaultExe = $s.DefaultExe; CustomExe = $s.CustomExe
      NewKey = $s.NewKey; LegacyKey = $s.LegacyKey
    }
    Write-Host '::endgroup::'
  }
}

# MSI: a major upgrade from 0.29.0 should leave a single 0.29.1 entry.
Write-Host '::group::msi'
Reset-Install
Start-Process msiexec -ArgumentList '/i', (Resolve-Path (Join-Path $Old 'clavix_0.29.0_x64_en-US.msi')), '/qn' -Wait
Start-Process msiexec -ArgumentList '/i', (Resolve-Path (Join-Path $New 'hook.msi')), '/qn' -Wait
$entries = Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' |
  ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -eq 'clavix' }
$entries | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation | Format-List | Out-String | Write-Host
$msiOk = (@($entries).Count -eq 1) -and ($entries.DisplayVersion -like '0.29.1*') -and ($entries.Publisher -eq 'clavix')
$results += [pscustomobject]@{
  Variant = 'msi'; Case = 'major upgrade'; Pass = $msiOk; Exit = '-'; Errors = ''
  Version = (@($entries).DisplayVersion -join ', '); Location = (@($entries).InstallLocation -join ', ')
  DefaultExe = '-'; CustomExe = '-'; NewKey = '-'; LegacyKey = '-'
}
Write-Host '::endgroup::'

$results | Format-Table -AutoSize | Out-String -Width 400 | Write-Host
$md = @('| Variant | Case | Pass | Exit | Version | Location | Default exe | Custom exe | New key | Legacy key | Errors |', '|---|---|---|---|---|---|---|---|---|---|---|')
$md += $results | ForEach-Object { "| $($_.Variant) | $($_.Case) | $($_.Pass) | $($_.Exit) | $($_.Version) | $($_.Location) | $($_.DefaultExe) | $($_.CustomExe) | $($_.NewKey) | $($_.LegacyKey) | $($_.Errors) |" }
$md -join "`n" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY

# The no-hook variant is the baseline that shows the problem; only the
# shipped configuration has to pass.
$failed = $results | Where-Object { $_.Variant -ne 'nohook' -and -not $_.Pass }
if ($failed) { throw "Upgrade failed: $(($failed | ForEach-Object { "$($_.Variant)/$($_.Case)" }) -join ', ')" }
