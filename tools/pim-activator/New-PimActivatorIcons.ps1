#Requires -Version 5.1
<#
.SYNOPSIS
  Builds the PIM Activator's toolbar / extension icons (icons\icon-16/32/48/128.png) from the brand icon, cropped to the
  shield so it fills the icon (owner 2026-10-15: "can you make logo in pim acticator bigger. too smal"). The earlier icons
  carried the source file's own margin: the shield used ~58 % of each icon.

.DESCRIPTION
  Reads the brand icon (default: C:\logos\Invardia-PIMManager-logo\Invardia-PIMManager-logo\icon\invardia-icon-1024.png),
  finds the visible shape (alpha > 20), crops to it, and draws it centred so its longer side is -Fill of each size
  (default 0.94), high-quality bicubic, transparent background. No module; System.Drawing only (Windows).

.EXAMPLE
  ./New-PimActivatorIcons.ps1
#>
[CmdletBinding()]
param(
    [string]$Source = 'C:\logos\Invardia-PIMManager-logo\Invardia-PIMManager-logo\icon\invardia-icon-1024.png',
    [string]$OutDir = (Join-Path $PSScriptRoot 'icons'),
    [ValidateRange(0.5, 1.0)][double]$Fill = 0.94,
    [int[]]$Sizes = @(16, 32, 48, 128)
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
if (-not (Test-Path -LiteralPath $Source)) { throw "brand icon not found: $Source" }
$src = [System.Drawing.Bitmap]::FromFile($Source)
try {
    $minX = $src.Width; $minY = $src.Height; $maxX = -1; $maxY = -1
    for ($y = 0; $y -lt $src.Height; $y++) { for ($x = 0; $x -lt $src.Width; $x++) {
        if ($src.GetPixel($x, $y).A -gt 20) { if ($x -lt $minX) { $minX = $x }; if ($y -lt $minY) { $minY = $y }; if ($x -gt $maxX) { $maxX = $x }; if ($y -gt $maxY) { $maxY = $y } } } }
    if ($maxX -lt 0) { throw 'the brand icon has no visible pixels' }
    $crop = New-Object System.Drawing.Rectangle $minX, $minY, ($maxX - $minX + 1), ($maxY - $minY + 1)
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    foreach ($s in $Sizes) {
        $scale = ($s * $Fill) / [Math]::Max($crop.Width, $crop.Height)
        $w = [int][Math]::Round($crop.Width * $scale); $h = [int][Math]::Round($crop.Height * $scale)
        $dst = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [System.Drawing.Graphics]::FromImage($dst)
        try {
            $g.Clear([System.Drawing.Color]::Transparent)
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $dest = New-Object System.Drawing.Rectangle ([int](($s - $w) / 2)), ([int](($s - $h) / 2)), $w, $h
            $g.DrawImage($src, $dest, $crop, [System.Drawing.GraphicsUnit]::Pixel)
        } finally { $g.Dispose() }
        $out = Join-Path $OutDir "icon-$s.png"
        $dst.Save($out, [System.Drawing.Imaging.ImageFormat]::Png); $dst.Dispose()
        "icon-$s.png  shape ${w}x$h of ${s}x$s"
    }
} finally { $src.Dispose() }
