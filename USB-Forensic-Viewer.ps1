# USB Forensic Viewer - Cyber Security Tool
# Displays all USB device history with forensic details
# Requires: Windows, PowerShell 5+, Run as Administrator for full data

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ── Forensic data collector ──────────────────────────────────────────────────

# Query Windows Event Log for USB plug/unplug timestamps
function Get-USBEventHistory {
    $history = @{}

    $logSources = @(
        @{ Log="System"; PlugIds=@(20001,20003); UnplugIds=@(20009,20010,20011) }
        @{ Log="Microsoft-Windows-Kernel-PnP/Configuration"; PlugIds=@(400); UnplugIds=@(410) }
        @{ Log="Microsoft-Windows-DriverFrameworks-UserMode/Operational"; PlugIds=@(2003); UnplugIds=@(2100,2101) }
    )

    foreach ($src in $logSources) {
        try {
            $allIds   = $src.PlugIds + $src.UnplugIds
            $xpFilter = ($allIds | ForEach-Object { "EventID=$_" }) -join " or "
            $evts = Get-WinEvent -LogName $src.Log -FilterXPath "*[System[($xpFilter)]]" `
                        -MaxEvents 5000 -ErrorAction SilentlyContinue
            foreach ($evt in $evts) {
                $devId = $null
                try {
                    $xml   = [xml]$evt.ToXml()
                    $nodes = $xml.Event.EventData.Data
                    foreach ($n in $nodes) {
                        $v = if ($n -is [string]) { $n } else { $n.'#text' }
                        if ($v -and $v -match "USB\\") { $devId = $v; break }
                    }
                } catch {}
                if (-not $devId -or $devId -notmatch "VID_") { continue }

                if ($devId -match "VID_([0-9A-Fa-f]+)&PID_([0-9A-Fa-f]+)") {
                    $key = "VID_$($Matches[1].ToUpper())&PID_$($Matches[2].ToUpper())"
                } else { continue }

                if (-not $history[$key]) {
                    $history[$key] = @{ LastPlug=$null; LastUnplug=$null; Events=@() }
                }

                $t = $evt.TimeCreated
                if ($evt.Id -in $src.PlugIds) {
                    if (-not $history[$key].LastPlug -or $t -gt $history[$key].LastPlug) {
                        $history[$key].LastPlug = $t
                    }
                    $history[$key].Events += "PLUG   $($t.ToString('yyyy-MM-dd HH:mm:ss'))  [EventID $($evt.Id)]"
                } else {
                    if (-not $history[$key].LastUnplug -or $t -gt $history[$key].LastUnplug) {
                        $history[$key].LastUnplug = $t
                    }
                    $history[$key].Events += "UNPLUG $($t.ToString('yyyy-MM-dd HH:mm:ss'))  [EventID $($evt.Id)]"
                }
            }
        } catch {}
    }

    return $history
}

function Get-USBForensicData {
    $devices = @()

    # Pull all USB entries from registry (historical + current)
    $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    $usbStor     = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

    # Helper: registry timestamp to readable date
    function Convert-RegistryTime($regKey) {
        try {
            $nativeKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $regKey -replace "HKLM:\\", ""
            )
            if ($nativeKey) {
                # LastWriteTime via reflection
                $info = $nativeKey.GetType().GetMethod(
                    "InternalGetSubKeyNames",
                    [System.Reflection.BindingFlags]"NonPublic,Instance"
                )
                return $nativeKey.LastWriteTime
            }
        } catch {}
        return $null
    }

    # ── USBSTOR (Mass Storage devices) ───────────────────────────────────────
    if (Test-Path $usbStor) {
        Get-ChildItem $usbStor -ErrorAction SilentlyContinue | ForEach-Object {
            $classKey = $_
            $friendlyType = $classKey.PSChildName -replace "Disk&Ven_","" -replace "&Prod_"," | " -replace "&Rev_"," Rev:"
            Get-ChildItem $classKey.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $instanceKey = $_
                $serial = $instanceKey.PSChildName
                $props  = Get-ItemProperty $instanceKey.PSPath -ErrorAction SilentlyContinue

                # Get last plug date from Windows Setup API log or registry timestamps
                $lastPlug = $null
                try {
                    $subKeys = Get-ChildItem $instanceKey.PSPath -ErrorAction SilentlyContinue
                    foreach ($sk in $subKeys) {
                        $skProps = Get-ItemProperty $sk.PSPath -ErrorAction SilentlyContinue
                        if ($skProps.LastArrivalDate) { $lastPlug = $skProps.LastArrivalDate }
                    }
                } catch {}

                # Fallback: setupapi.dev.log
                if (-not $lastPlug) {
                    $lastPlug = (Get-Item $instanceKey.PSPath).LastWriteTime
                }

                $vendor  = ($classKey.PSChildName -split "Ven_")[1] -split "&" | Select-Object -First 1
                $product = ($classKey.PSChildName -split "Prod_")[1] -split "&" | Select-Object -First 1
                $rev     = ($classKey.PSChildName -split "Rev_")[1]  -split "&" | Select-Object -First 1

                # Drive letter from MountedDevices + SYSTEM
                $driveLetter = ""
                try {
                    $mountPath = "HKLM:\SYSTEM\MountedDevices"
                    # basic lookup via serial in friendly name paths
                } catch {}

                $devices += [PSCustomObject]@{
                    DeviceName    = if ($props.FriendlyName) { $props.FriendlyName } else { "$vendor $product" }
                    Description   = if ($props.DeviceDesc)   { $props.DeviceDesc -replace "@.*;" } else { "Mass Storage" }
                    DeviceType    = "Mass Storage"
                    VendorID      = ""
                    ProductID     = ""
                    SerialNumber  = $serial -replace "&0$","" -replace "&1$",""
                    Manufacturer  = if ($props.Mfg) { $props.Mfg -replace "@.*;" } else { $vendor }
                    VendorName    = $vendor
                    ProductName   = $product
                    FirmwareRev   = $rev
                    InstanceID    = $instanceKey.PSChildName
                    LastPlug      = $lastPlug
                    LastUnplug    = $null
                    Connected     = $false
                    SafeToUnplug  = $true
                    Disabled      = $false
                    DriveLetter   = $driveLetter
                    USBClass      = "08"
                    USBSubClass   = "06"
                    USBProtocol   = "50"
                    USBVersion    = "2.00"
                    ServiceName   = if ($props.Service) { $props.Service } else { "disk" }
                    DriverFile    = "disk.sys"
                    PowerMA       = ""
                    History       = @()
                }
            }
        }
    }

    # ── Live devices via WMI ─────────────────────────────────────────────────
    $liveUSB = @{}
    try {
        Get-WmiObject Win32_USBControllerDevice -ErrorAction SilentlyContinue | ForEach-Object {
            $dep = [wmi]$_.Dependent
            $key = $dep.DeviceID -replace "USB\\",""
            $liveUSB[$key] = $dep
        }
    } catch {}

    # ── USB (HID + other) from Enum\USB ─────────────────────────────────────
    if (Test-Path $usbStorPath) {
        Get-ChildItem $usbStorPath -ErrorAction SilentlyContinue | ForEach-Object {
            $vidpid = $_.PSChildName  # e.g. VID_413C&PID_2514
            $vid = ($vidpid -split "VID_")[1] -split "&" | Select-Object -First 1
            $pid_ = ($vidpid -split "PID_")[1] -split "&" | Select-Object -First 1

            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $instKey = $_
                $props   = Get-ItemProperty $instKey.PSPath -ErrorAction SilentlyContinue
                $lastPlug = (Get-Item $instKey.PSPath -ErrorAction SilentlyContinue).LastWriteTime

                # Check if connected right now
                $isConnected = $liveUSB.ContainsKey($instKey.PSChildName) -or
                               ($props.ConfigFlags -eq 0)

                $devDesc  = if ($props.DeviceDesc) { $props.DeviceDesc -replace "@.*;" } else { $vidpid }
                $devClass = if ($props.Class)       { $props.Class } else { "Unknown" }

                $devType = switch ($devClass) {
                    "HIDClass"    { "HID (Human Interface Device)" }
                    "Image"       { "Still Imaging" }
                    "Bluetooth"   { "Bluetooth Device" }
                    "Net"         { "Network Adapter" }
                    "AudioEndpoint" { "Audio Device" }
                    "MEDIA"       { "Audio/Video" }
                    default       { if ($devDesc -match "Hub") { "USB Hub" } else { "Unknown" } }
                }

                # Skip pure hubs unless interesting
                $devices += [PSCustomObject]@{
                    DeviceName    = if ($props.FriendlyName) { $props.FriendlyName } else { $devDesc }
                    Description   = $devDesc
                    DeviceType    = $devType
                    VendorID      = $vid
                    ProductID     = $pid_
                    SerialNumber  = ""
                    Manufacturer  = if ($props.Mfg) { $props.Mfg -replace "@.*;" } else { "" }
                    VendorName    = ""
                    ProductName   = ""
                    FirmwareRev   = ""
                    InstanceID    = $instKey.PSChildName
                    LastPlug      = $lastPlug
                    LastUnplug    = $null
                    Connected     = $isConnected
                    SafeToUnplug  = $true
                    Disabled      = ($props.ConfigFlags -band 1) -eq 1
                    DriveLetter   = ""
                    USBClass      = ""
                    USBSubClass   = ""
                    USBProtocol   = ""
                    USBVersion    = "2.00"
                    ServiceName   = if ($props.Service) { $props.Service } else { "" }
                    DriverFile    = ""
                    PowerMA       = ""
                    History       = @()
                }
            }
        }
    }

    # ── Enrich from Windows Event Log (plug/unplug timestamps + history) ─────
    $statusLabel.Text = "  Querying event logs..." 2>$null
    $evtHistory = Get-USBEventHistory
    foreach ($d in $devices) {
        if ($d.VendorID -and $d.ProductID) {
            $key = "VID_$($d.VendorID.ToUpper())&PID_$($d.ProductID.ToUpper())"
            if ($evtHistory[$key]) {
                $h = $evtHistory[$key]
                if ($h.LastPlug)   { $d.LastPlug   = $h.LastPlug }
                if ($h.LastUnplug) { $d.LastUnplug = $h.LastUnplug }
                if ($h.Events)     { $d.History    = $h.Events | Sort-Object -Descending }
            }
        }
    }

    # ── Fallback: setupapi.dev.log for devices with no event history ──────────
    $setupLog = "$env:WINDIR\inf\setupapi.dev.log"
    if (Test-Path $setupLog) {
        try {
            $logContent = Get-Content $setupLog -ErrorAction SilentlyContinue
            $i = 0
            foreach ($line in $logContent) {
                if ($line -match ">>>  \[Device Install.*\]" -and
                    $line -match "USB\\VID_([0-9A-Fa-f]+)&PID_([0-9A-Fa-f]+)") {
                    $vid_  = $Matches[1].ToUpper()
                    $pid__ = $Matches[2].ToUpper()
                    $ts    = if ($i -gt 0 -and $logContent[$i-1] -match ">>>  Section start (\S+ \S+)") { $Matches[1] } else { $null }
                    if ($ts) {
                        foreach ($d in $devices) {
                            if ($d.VendorID.ToUpper() -eq $vid_ -and $d.ProductID.ToUpper() -eq $pid__ -and -not $d.LastPlug) {
                                try { $d.LastPlug = [datetime]::Parse($ts) } catch {}
                            }
                        }
                    }
                }
                $i++
            }
        } catch {}
    }

    return $devices | Sort-Object LastPlug -Descending
}

# ── Build GUI ────────────────────────────────────────────────────────────────

$form = New-Object System.Windows.Forms.Form
$form.Text          = "USB Forensic Viewer - Cyber Security Edition"
$form.Size          = New-Object System.Drawing.Size(1300, 720)
$form.StartPosition = "CenterScreen"
$form.BackColor     = [System.Drawing.Color]::FromArgb(18, 18, 28)
$form.ForeColor     = [System.Drawing.Color]::FromArgb(0, 230, 180)
$form.Font          = New-Object System.Drawing.Font("Consolas", 9)
$form.Icon          = [System.Drawing.SystemIcons]::Shield

# ── Title bar strip ──────────────────────────────────────────────────────────
$titlePanel = New-Object System.Windows.Forms.Panel
$titlePanel.Dock      = "Top"
$titlePanel.Height    = 48
$titlePanel.BackColor = [System.Drawing.Color]::FromArgb(10, 10, 20)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text      = "  [USB FORENSIC VIEWER]   Plug/Unplug History + Device Intelligence"
$titleLabel.Dock      = "Fill"
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 180)
$titleLabel.Font      = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
$titleLabel.TextAlign = "MiddleLeft"
$titlePanel.Controls.Add($titleLabel)
$form.Controls.Add($titlePanel)

# ── Toolbar ──────────────────────────────────────────────────────────────────
$toolbar = New-Object System.Windows.Forms.Panel
$toolbar.Dock      = "Top"
$toolbar.Height    = 38
$toolbar.BackColor = [System.Drawing.Color]::FromArgb(22, 22, 38)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text      = "[ REFRESH ]"
$btnRefresh.Width     = 110
$btnRefresh.Height    = 28
$btnRefresh.Left      = 8
$btnRefresh.Top       = 5
$btnRefresh.BackColor = [System.Drawing.Color]::FromArgb(0, 80, 60)
$btnRefresh.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 180)
$btnRefresh.FlatStyle = "Flat"
$btnRefresh.Font      = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
$toolbar.Controls.Add($btnRefresh)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text      = "[ EXPORT CSV ]"
$btnExport.Width     = 120
$btnExport.Height    = 28
$btnExport.Left      = 126
$btnExport.Top       = 5
$btnExport.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 80)
$btnExport.ForeColor = [System.Drawing.Color]::FromArgb(100, 180, 255)
$btnExport.FlatStyle = "Flat"
$btnExport.Font      = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
$toolbar.Controls.Add($btnExport)

$btnExportHTML = New-Object System.Windows.Forms.Button
$btnExportHTML.Text      = "[ EXPORT HTML ]"
$btnExportHTML.Width     = 130
$btnExportHTML.Height    = 28
$btnExportHTML.Left      = 254
$btnExportHTML.Top       = 5
$btnExportHTML.BackColor = [System.Drawing.Color]::FromArgb(60, 30, 80)
$btnExportHTML.ForeColor = [System.Drawing.Color]::FromArgb(200, 130, 255)
$btnExportHTML.FlatStyle = "Flat"
$btnExportHTML.Font      = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
$toolbar.Controls.Add($btnExportHTML)

# Filter box
$filterLabel = New-Object System.Windows.Forms.Label
$filterLabel.Text      = "  FILTER:"
$filterLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 180)
$filterLabel.Width     = 65
$filterLabel.Height    = 28
$filterLabel.Left      = 400
$filterLabel.Top       = 8
$toolbar.Controls.Add($filterLabel)

$filterBox = New-Object System.Windows.Forms.TextBox
$filterBox.Width     = 200
$filterBox.Height    = 24
$filterBox.Left      = 465
$filterBox.Top       = 7
$filterBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 50)
$filterBox.ForeColor = [System.Drawing.Color]::FromArgb(0, 230, 180)
$filterBox.BorderStyle = "FixedSingle"
$toolbar.Controls.Add($filterBox)

# Connected only toggle
$chkConnected = New-Object System.Windows.Forms.CheckBox
$chkConnected.Text      = "Connected Only"
$chkConnected.Width     = 130
$chkConnected.Height    = 28
$chkConnected.Left      = 680
$chkConnected.Top       = 7
$chkConnected.ForeColor = [System.Drawing.Color]::FromArgb(0, 230, 180)
$toolbar.Controls.Add($chkConnected)

# Status label right side
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text      = ""
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 100)
$statusLabel.Width     = 420
$statusLabel.Height    = 28
$statusLabel.Left      = 820
$statusLabel.Top       = 8
$statusLabel.TextAlign = "MiddleLeft"
$toolbar.Controls.Add($statusLabel)

$form.Controls.Add($toolbar)

# ── Split: ListView top, Details panel bottom ─────────────────────────────────
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock        = "Fill"
$split.Orientation = "Horizontal"
$split.SplitterDistance = 380
$split.BackColor   = [System.Drawing.Color]::FromArgb(18, 18, 28)
$form.Controls.Add($split)

# ── ListView ─────────────────────────────────────────────────────────────────
$listView = New-Object System.Windows.Forms.ListView
$listView.Dock          = "Fill"
$listView.View          = "Details"
$listView.FullRowSelect = $true
$listView.GridLines     = $true
$listView.BackColor     = [System.Drawing.Color]::FromArgb(14, 14, 24)
$listView.ForeColor     = [System.Drawing.Color]::FromArgb(0, 220, 170)
$listView.Font          = New-Object System.Drawing.Font("Consolas", 8.5)
$listView.BorderStyle   = "None"
$listView.OwnerDraw     = $true

$columns = @(
    @{T="Device Name";    W=200},
    @{T="Description";    W=170},
    @{T="Device Type";    W=160},
    @{T="Connected";      W=75},
    @{T="Safe To Unplug"; W=90},
    @{T="Disabled";       W=70},
    @{T="Last Plug Date";   W=155},
    @{T="Last Unplug Date"; W=155},
    @{T="Serial Number";    W=130},
    @{T="VendorID";       W=70},
    @{T="ProductID";      W=70},
    @{T="Manufacturer";   W=130},
    @{T="Drive Letter";   W=80},
    @{T="Service";        W=90}
)

foreach ($col in $columns) {
    $c = New-Object System.Windows.Forms.ColumnHeader
    $c.Text  = $col.T
    $c.Width = $col.W
    $listView.Columns.Add($c) | Out-Null
}

$split.Panel1.Controls.Add($listView)

# ── Owner-draw column headers (dark theme) ────────────────────────────────────
$hdrBrush  = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(0, 45, 34))
$hdrTxtBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(0, 255, 180))
$hdrPen    = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(0, 140, 100))
$hdrFont   = New-Object System.Drawing.Font("Consolas", 8.5, [System.Drawing.FontStyle]::Bold)
$hdrSF     = New-Object System.Drawing.StringFormat
$hdrSF.Alignment     = [System.Drawing.StringAlignment]::Near
$hdrSF.LineAlignment = [System.Drawing.StringAlignment]::Center
$hdrSF.FormatFlags   = [System.Drawing.StringFormatFlags]::NoWrap

$listView.Add_DrawColumnHeader({
    param($s, $e)
    $e.Graphics.FillRectangle($hdrBrush, $e.Bounds)
    $e.Graphics.DrawLine($hdrPen, $e.Bounds.Left,  $e.Bounds.Bottom - 1, $e.Bounds.Right, $e.Bounds.Bottom - 1)
    $e.Graphics.DrawLine($hdrPen, $e.Bounds.Right - 1, $e.Bounds.Top, $e.Bounds.Right - 1, $e.Bounds.Bottom)
    $textRect = [System.Drawing.RectangleF]::new($e.Bounds.X + 5, $e.Bounds.Y, $e.Bounds.Width - 6, $e.Bounds.Height)
    $e.Graphics.DrawString($e.Header.Text, $hdrFont, $hdrTxtBrush, $textRect, $hdrSF)
})

$listView.Add_DrawItem({
    param($s, $e)
    $e.DrawDefault = $true
})

$listView.Add_DrawSubItem({
    param($s, $e)
    $e.DrawDefault = $true
})

# ── Details Panel ─────────────────────────────────────────────────────────────
$detailPanel = New-Object System.Windows.Forms.Panel
$detailPanel.Dock      = "Fill"
$detailPanel.BackColor = [System.Drawing.Color]::FromArgb(10, 10, 18)
$split.Panel2.Controls.Add($detailPanel)

$detailTitle = New-Object System.Windows.Forms.Label
$detailTitle.Text      = "  DEVICE FORENSIC DETAILS"
$detailTitle.Dock      = "Top"
$detailTitle.Height    = 26
$detailTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 180)
$detailTitle.Font      = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
$detailTitle.BackColor = [System.Drawing.Color]::FromArgb(0, 50, 40)
$detailPanel.Controls.Add($detailTitle)

# Inner horizontal split: left = property boxes, right = history log
$detailInner = New-Object System.Windows.Forms.SplitContainer
$detailInner.Dock        = "Fill"
$detailInner.Orientation = "Vertical"
$detailInner.BackColor   = [System.Drawing.Color]::FromArgb(10, 10, 18)
$detailPanel.Controls.Add($detailInner)

$detailFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$detailFlow.Dock          = "Fill"
$detailFlow.FlowDirection = "LeftToRight"
$detailFlow.WrapContents  = $true
$detailFlow.BackColor     = [System.Drawing.Color]::FromArgb(10, 10, 18)
$detailFlow.AutoScroll    = $true
$detailInner.Panel1.Controls.Add($detailFlow)

# History pane (right)
$histTitle = New-Object System.Windows.Forms.Label
$histTitle.Text      = "  PLUG / UNPLUG EVENT HISTORY  (newest first)"
$histTitle.Dock      = "Top"
$histTitle.Height    = 22
$histTitle.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 80)
$histTitle.Font      = New-Object System.Drawing.Font("Consolas", 8, [System.Drawing.FontStyle]::Bold)
$histTitle.BackColor = [System.Drawing.Color]::FromArgb(40, 28, 0)
$detailInner.Panel2.Controls.Add($histTitle)

$script:histBox = New-Object System.Windows.Forms.RichTextBox
$script:histBox.Dock        = "Fill"
$script:histBox.BackColor   = [System.Drawing.Color]::FromArgb(8, 8, 14)
$script:histBox.ForeColor   = [System.Drawing.Color]::FromArgb(200, 200, 140)
$script:histBox.Font        = New-Object System.Drawing.Font("Consolas", 8.5)
$script:histBox.ReadOnly    = $true
$script:histBox.BorderStyle = "None"
$script:histBox.ScrollBars  = "Vertical"
$detailInner.Panel2.Controls.Add($script:histBox)

# ── Data store ────────────────────────────────────────────────────────────────
$script:allDevices = @()

function Add-DetailBox($label, $value) {
    $box = New-Object System.Windows.Forms.GroupBox
    $box.Text      = $label
    $box.Width     = 220
    $box.Height    = 52
    $box.ForeColor = [System.Drawing.Color]::FromArgb(100, 180, 255)
    $box.Font      = New-Object System.Drawing.Font("Consolas", 7.5)
    $box.BackColor = [System.Drawing.Color]::FromArgb(16, 16, 30)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text      = if ($value) { $value } else { "-" }
    $lbl.Dock      = "Fill"
    $lbl.ForeColor = [System.Drawing.Color]::FromArgb(0, 230, 170)
    $lbl.Font      = New-Object System.Drawing.Font("Consolas", 8.5, [System.Drawing.FontStyle]::Bold)
    $lbl.TextAlign = "MiddleCenter"
    $box.Controls.Add($lbl)
    $detailFlow.Controls.Add($box)
}

function Show-DeviceDetails($dev) {
    $detailFlow.Controls.Clear()
    if (-not $dev) { return }

    $fields = [ordered]@{
        "Device Name"       = $dev.DeviceName
        "Description"       = $dev.Description
        "Device Type"       = $dev.DeviceType
        "Connected"         = if ($dev.Connected) { "YES" } else { "No" }
        "Safe To Unplug"    = if ($dev.SafeToUnplug) { "Yes" } else { "NO" }
        "Disabled"          = if ($dev.Disabled) { "YES" } else { "No" }
        "Last Plug Date"    = if ($dev.LastPlug) { $dev.LastPlug.ToString("yyyy-MM-dd  HH:mm:ss") } else { "Unknown" }
        "Last Unplug Date"  = if ($dev.LastUnplug) { $dev.LastUnplug.ToString("yyyy-MM-dd  HH:mm:ss") } else { "Unknown" }
        "Serial Number"     = $dev.SerialNumber
        "VendorID"          = $dev.VendorID
        "ProductID"         = $dev.ProductID
        "Manufacturer"      = $dev.Manufacturer
        "Vendor Name"       = $dev.VendorName
        "Product Name"      = $dev.ProductName
        "Firmware Rev"      = $dev.FirmwareRev
        "Drive Letter"      = $dev.DriveLetter
        "USB Class"         = $dev.USBClass
        "USB SubClass"      = $dev.USBSubClass
        "USB Protocol"      = $dev.USBProtocol
        "USB Version"       = $dev.USBVersion
        "Service Name"      = $dev.ServiceName
        "Driver File"       = $dev.DriverFile
        "Power (mA)"        = $dev.PowerMA
        "Instance ID"       = $dev.InstanceID
    }

    foreach ($k in $fields.Keys) {
        Add-DetailBox $k $fields[$k]
    }

    # Populate history log pane
    $script:histBox.Clear()
    if ($dev.History -and $dev.History.Count -gt 0) {
        foreach ($entry in $dev.History) {
            if ($entry -match "^PLUG") {
                $script:histBox.SelectionColor = [System.Drawing.Color]::FromArgb(0, 220, 140)
            } else {
                $script:histBox.SelectionColor = [System.Drawing.Color]::FromArgb(255, 100, 80)
            }
            $script:histBox.AppendText("$entry`n")
        }
    } else {
        $script:histBox.SelectionColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
        $script:histBox.AppendText("No event log history found for this device.`n")
        $script:histBox.AppendText("Tip: Run as Administrator for full event log access.")
    }
}

# ── Populate ListView ────────────────────────────────────────────────────────
function Populate-List($devices) {
    $listView.Items.Clear()
    $connectedCount = ($devices | Where-Object { $_.Connected }).Count

    foreach ($d in $devices) {
        $item = New-Object System.Windows.Forms.ListViewItem($d.DeviceName)
        $item.SubItems.Add($d.Description)             | Out-Null
        $item.SubItems.Add($d.DeviceType)              | Out-Null
        $item.SubItems.Add($(if ($d.Connected) { "Yes" } else { "No" })) | Out-Null
        $item.SubItems.Add($(if ($d.SafeToUnplug) { "Yes" } else { "No" })) | Out-Null
        $item.SubItems.Add($(if ($d.Disabled) { "Yes" } else { "No" })) | Out-Null
        $item.SubItems.Add($(if ($d.LastPlug)   { $d.LastPlug.ToString("yyyy-MM-dd HH:mm:ss") }   else { "Unknown" })) | Out-Null
        $item.SubItems.Add($(if ($d.LastUnplug) { $d.LastUnplug.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" })) | Out-Null
        $item.SubItems.Add($d.SerialNumber)            | Out-Null
        $item.SubItems.Add($d.VendorID)                | Out-Null
        $item.SubItems.Add($d.ProductID)               | Out-Null
        $item.SubItems.Add($d.Manufacturer)            | Out-Null
        $item.SubItems.Add($d.DriveLetter)             | Out-Null
        $item.SubItems.Add($d.ServiceName)             | Out-Null
        $item.Tag = $d

        # Color coding
        if ($d.Connected) {
            $item.BackColor = [System.Drawing.Color]::FromArgb(0, 40, 30)
            $item.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 160)
        } else {
            $item.BackColor = [System.Drawing.Color]::FromArgb(14, 14, 24)
            $item.ForeColor = [System.Drawing.Color]::FromArgb(130, 130, 160)
        }

        $listView.Items.Add($item) | Out-Null
    }

    $statusLabel.Text = "  $($devices.Count) devices  /  $connectedCount connected  |  Scanned: $(Get-Date -f 'HH:mm:ss')"
}

function Apply-Filter {
    $text = $filterBox.Text.Trim().ToLower()
    $connOnly = $chkConnected.Checked
    $filtered = $script:allDevices | Where-Object {
        $match = $true
        if ($text) {
            $match = ($_.DeviceName + $_.Description + $_.DeviceType + $_.SerialNumber + $_.VendorID + $_.ProductID + $_.Manufacturer).ToLower() -match [regex]::Escape($text)
        }
        if ($connOnly) { $match = $match -and $_.Connected }
        $match
    }
    Populate-List $filtered
}

function Load-Data {
    $statusLabel.Text    = "  Scanning registry..."
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 0)
    $form.Refresh()
    $script:allDevices = Get-USBForensicData
    Apply-Filter
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 200, 100)
}

# ── Real-time USB device monitoring (WMI) ────────────────────────────────
$script:usbWatcher = $null

function Start-USBMonitor {
    try {
        $q = New-Object System.Management.WqlEventQuery(
            "SELECT * FROM Win32_DeviceChangeEvent"
        )
        $script:usbWatcher = New-Object System.Management.ManagementEventWatcher($q)
        $script:usbWatcher.add_EventArrived({
            Start-Sleep -Milliseconds 1400   # let registry + event log settle
            [void]$form.BeginInvoke([System.Action]{
                $statusLabel.Text      = "  Device change detected ─ refreshing..."
                $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 80)
                Load-Data
            })
        })
        $script:usbWatcher.Start()
    } catch {}
}

function Stop-USBMonitor {
    try {
        if ($script:usbWatcher) {
            $script:usbWatcher.Stop()
            $script:usbWatcher.Dispose()
            $script:usbWatcher = $null
        }
    } catch {}
}

# ── Auto-refresh timer (15-second fallback) ───────────────────────────────
$autoTimer = New-Object System.Windows.Forms.Timer
$autoTimer.Interval = 15000
$autoTimer.Add_Tick({ Load-Data })

# ── Events ────────────────────────────────────────────────────────────────────
$btnRefresh.Add_Click({ Load-Data })

$filterBox.Add_TextChanged({ Apply-Filter })
$chkConnected.Add_CheckedChanged({ Apply-Filter })

$listView.Add_SelectedIndexChanged({
    if ($listView.SelectedItems.Count -gt 0) {
        Show-DeviceDetails $listView.SelectedItems[0].Tag
    }
})

# Right-click context menu
$ctxMenu = New-Object System.Windows.Forms.ContextMenuStrip
$ctxMenu.BackColor = [System.Drawing.Color]::FromArgb(22, 22, 38)
$ctxMenu.ForeColor = [System.Drawing.Color]::FromArgb(0, 220, 170)

$menuCopySerial = New-Object System.Windows.Forms.ToolStripMenuItem
$menuCopySerial.Text = "Copy Serial Number"
$menuCopySerial.Add_Click({
    if ($listView.SelectedItems.Count -gt 0) {
        $d = $listView.SelectedItems[0].Tag
        if ($d.SerialNumber) { [System.Windows.Forms.Clipboard]::SetText($d.SerialNumber) }
    }
})
$ctxMenu.Items.Add($menuCopySerial) | Out-Null

$menuCopyAll = New-Object System.Windows.Forms.ToolStripMenuItem
$menuCopyAll.Text = "Copy All Details (JSON)"
$menuCopyAll.Add_Click({
    if ($listView.SelectedItems.Count -gt 0) {
        $d = $listView.SelectedItems[0].Tag
        $json = $d | ConvertTo-Json
        [System.Windows.Forms.Clipboard]::SetText($json)
    }
})
$ctxMenu.Items.Add($menuCopyAll) | Out-Null

$listView.ContextMenuStrip = $ctxMenu

# ── Export CSV ────────────────────────────────────────────────────────────────
$btnExport.Add_Click({
    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.Filter   = "CSV files (*.csv)|*.csv"
    $save.FileName = "USB_Forensic_Report_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"
    if ($save.ShowDialog() -eq "OK") {
        $script:allDevices | Select-Object DeviceName,Description,DeviceType,Connected,SafeToUnplug,Disabled,
            @{N="LastPlugDate";E={if($_.LastPlug){$_.LastPlug.ToString("yyyy-MM-dd HH:mm:ss")}else{"Unknown"}}},
            @{N="LastUnplugDate";E={if($_.LastUnplug){$_.LastUnplug.ToString("yyyy-MM-dd HH:mm:ss")}else{"Unknown"}}},
            SerialNumber,VendorID,ProductID,Manufacturer,VendorName,ProductName,FirmwareRev,
            DriveLetter,USBClass,USBSubClass,USBProtocol,USBVersion,ServiceName,DriverFile,InstanceID |
            Export-Csv $save.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Exported to:`n$($save.FileName)", "Export Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# ── Export HTML ───────────────────────────────────────────────────────────────
$btnExportHTML.Add_Click({
    $save = New-Object System.Windows.Forms.SaveFileDialog
    $save.Filter   = "HTML files (*.html)|*.html"
    $save.FileName = "USB_Forensic_Report_$(Get-Date -f 'yyyyMMdd_HHmmss').html"
    if ($save.ShowDialog() -eq "OK") {
        $rows = $script:allDevices | ForEach-Object {
            $connColor  = if ($_.Connected) { "#00ff90" } else { "#888" }
            $lastPlug   = if ($_.LastPlug)   { $_.LastPlug.ToString("yyyy-MM-dd HH:mm:ss") }   else { "Unknown" }
            $lastUnplug = if ($_.LastUnplug) { $_.LastUnplug.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
            "<tr>
              <td>$($_.DeviceName)</td><td>$($_.Description)</td><td>$($_.DeviceType)</td>
              <td style='color:$connColor'>$(if($_.Connected){'YES'}else{'No'})</td>
              <td>$(if($_.SafeToUnplug){'Yes'}else{'No'})</td>
              <td>$($_.Disabled)</td>
              <td style='color:#ffd700'>$lastPlug</td>
              <td style='color:#ff7060'>$lastUnplug</td>
              <td>$($_.SerialNumber)</td><td>$($_.VendorID)</td><td>$($_.ProductID)</td>
              <td>$($_.Manufacturer)</td><td>$($_.DriveLetter)</td><td>$($_.ServiceName)</td>
            </tr>"
        }
        $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>USB Forensic Report - $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')</title>
<style>
  body{background:#0a0a12;color:#00e6b4;font-family:Consolas,monospace;font-size:12px;margin:20px}
  h1{color:#00ffb4;border-bottom:1px solid #00ffb4;padding-bottom:8px}
  p{color:#888}
  table{border-collapse:collapse;width:100%}
  th{background:#0a3028;color:#00ffb4;padding:6px 10px;text-align:left;border:1px solid #1a4a38}
  td{padding:5px 10px;border:1px solid #1a2030}
  tr:hover td{background:#101828}
  tr:nth-child(even) td{background:#0c0c1e}
</style></head><body>
<h1>USB Forensic Report</h1>
<p>Generated: $(Get-Date -f 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $env:USERNAME</p>
<table>
<tr>
  <th>Device Name</th><th>Description</th><th>Device Type</th><th>Connected</th>
  <th>Safe Unplug</th><th>Disabled</th><th>Last Plug Date</th><th>Last Unplug Date</th>
  <th>Serial Number</th><th>VendorID</th><th>ProductID</th>
  <th>Manufacturer</th><th>Drive Letter</th><th>Service</th>
</tr>
$($rows -join "`n")
</table></body></html>
"@
        $html | Out-File $save.FileName -Encoding UTF8
        Start-Process $save.FileName
    }
})

# ── Keyboard shortcut: F5 = Refresh ──────────────────────────────────────────
$form.Add_KeyDown({
    if ($_.KeyCode -eq "F5") { Load-Data }
})
$form.KeyPreview = $true

# ── Initial load ─────────────────────────────────────────────────────────────
$form.Add_Shown({
    try { $detailInner.SplitterDistance = [int]($detailInner.Width * 0.65) } catch {}
    Load-Data
    Start-USBMonitor
    $autoTimer.Start()
})

$form.Add_FormClosing({
    $autoTimer.Stop()
    Stop-USBMonitor
})
$form.ShowDialog() | Out-Null
