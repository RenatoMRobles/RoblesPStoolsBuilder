# --- 0. C# NINJA CLOAK (INVISIBILIDAD NATIVA DE CONSOLA) ---
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0) | Out-Null

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- 1. POP-UPS DE SEGURIDAD (PREVENCIÓN SIMPLIFICADA) ---
$backupWarning = "Prior using this tool please make sure to create a back up of your existing configurations:`n`n" +
"- From the Management client > Click File > Create a Configuration backup > Save your .cnf file somewhere safe.`n`n" +
"- Optional: With SSMS (SQL Server Management Studio) > Login with your Administrator credentials > Expand the Databases node > Right click the 'Surveillance', 'Surveillance_IDP', and 'Surveillance_log' databases > Click Tasks > Backup > Create a .bak file backup and save it somewhere safe."

$resp1 = [System.Windows.Forms.MessageBox]::Show($backupWarning, "Backup Recommended", [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)

if ($resp1 -ne 'OK') { return }
# ELIMINADO EL SEGUNDO POP-UP POR DIRECTIVA DE USUARIO

# --- 2. DETECCIÓN DE VERSIONES ---
$installedModule = Get-Module -Name MilestonePSTools -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
$psToolsVer = if ($installedModule) { $installedModule.Version.ToString() } else { "Not Installed" }

$xpVersion = "Unknown"
$uninstallKeys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
$xpApp = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "Milestone XProtect Management Server" } | Select-Object -First 1

if ($xpApp -and $xpApp.DisplayVersion) { $xpVersion = $xpApp.DisplayVersion }

$neededPSTools = "Latest"
if ($xpVersion -match "^22\.2") { $neededPSTools = "25.1.50" }
elseif ($xpVersion -match "^22\.1") { $neededPSTools = "24.2.18" }
elseif ($xpVersion -match "^21\.2") { $neededPSTools = "24.1.30" }
elseif ($xpVersion -match "^21\.1") { $neededPSTools = "23.3.51" }
elseif ($xpVersion -match "^20\.") { $neededPSTools = "23.2.3" }
elseif ($xpVersion -match "^(1[0-9]\.)") { $neededPSTools = "Incompatible" }

# --- 3. CONFIGURACIÓN DE LA VENTANA PRINCIPAL (DARK MODE) ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "XProtect Report Builder - Advanced VMS Scanner"
$form.Size = New-Object System.Drawing.Size(460, 830) # Altura optimizada tras remover Device Pack
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::WhiteSmoke
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

# Extraer el icono del .exe compilado para que la ventana luzca profesional
try { $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon([System.Windows.Forms.Application]::ExecutablePath) } catch {}

$btnBackColor = [System.Drawing.Color]::FromArgb(60, 63, 65)

# --- 4. CONTROLES DE LA INTERFAZ ---
$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text = "[ Quick Install MilestonePSTools ]"
$btnInstall.Location = New-Object System.Drawing.Point(20, 20)
$btnInstall.Size = New-Object System.Drawing.Size(400, 35)
$btnInstall.BackColor = $btnBackColor
$btnInstall.FlatStyle = 'Flat'
$form.Controls.Add($btnInstall)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "[ Connect to Management Server ]"
$btnConnect.Location = New-Object System.Drawing.Point(20, 65)
$btnConnect.Size = New-Object System.Drawing.Size(400, 35)
$btnConnect.BackColor = $btnBackColor
$btnConnect.FlatStyle = 'Flat'
$form.Controls.Add($btnConnect)

$cbForceLogin = New-Object System.Windows.Forms.CheckBox
$cbForceLogin.Text = "Force new credentials prompt (Disable Auto-login)"
$cbForceLogin.Location = New-Object System.Drawing.Point(20, 105)
$cbForceLogin.Size = New-Object System.Drawing.Size(400, 20)
$cbForceLogin.ForeColor = [System.Drawing.Color]::LightCoral
$form.Controls.Add($cbForceLogin)

# Label de versiones limpio (Sin Device Pack)
$lblVersions = New-Object System.Windows.Forms.Label
$lblVersions.Text = "Installed PSTools: $psToolsVer`nXProtect Local Version: $xpVersion"
$lblVersions.Location = New-Object System.Drawing.Point(20, 135)
$lblVersions.Size = New-Object System.Drawing.Size(400, 35)
$lblVersions.ForeColor = [System.Drawing.Color]::YellowGreen
$lblVersions.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($lblVersions)

$lblServer = New-Object System.Windows.Forms.Label
$lblServer.Text = "Target Recording Server:"
$lblServer.Location = New-Object System.Drawing.Point(20, 175)
$lblServer.AutoSize = $true
$form.Controls.Add($lblServer)

$cboServer = New-Object System.Windows.Forms.ComboBox
$cboServer.Location = New-Object System.Drawing.Point(20, 195)
$cboServer.Size = New-Object System.Drawing.Size(400, 20)
$cboServer.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$cboServer.ForeColor = [System.Drawing.Color]::White
$cboServer.FlatStyle = 'Flat'
$cboServer.DropDownStyle = 'DropDown' 
$cboServer.Text = "enter here your RS Hostname or FQDN..."
$form.Controls.Add($cboServer)

$cboServer.Add_Enter({
    if ($cboServer.Text -eq "enter here your RS Hostname or FQDN...") {
        $cboServer.Text = ""
    }
})
$cboServer.Add_Leave({
    if ([string]::IsNullOrWhiteSpace($cboServer.Text)) {
        $cboServer.Text = "enter here your RS Hostname or FQDN..."
    }
})

$cbIgnoreDisabled = New-Object System.Windows.Forms.CheckBox
$cbIgnoreDisabled.Text = "Ignore disabled hardware/cameras (Faster processing)"
$cbIgnoreDisabled.Location = New-Object System.Drawing.Point(20, 225)
$cbIgnoreDisabled.Size = New-Object System.Drawing.Size(400, 20)
$cbIgnoreDisabled.ForeColor = [System.Drawing.Color]::Cyan
$cbIgnoreDisabled.Checked = $true
$form.Controls.Add($cbIgnoreDisabled)

$group = New-Object System.Windows.Forms.GroupBox
$group.Text = "Select Columns to Include"
$group.Location = New-Object System.Drawing.Point(20, 255)
$group.Size = New-Object System.Drawing.Size(400, 385)
$group.ForeColor = [System.Drawing.Color]::WhiteSmoke
$form.Controls.Add($group)

$yOffset = 20
$checkboxes = @{}
# Matriz de columnas purgada y validada
$columnNames = @("RecordingServer", "Hardware", "IP Address", "MAC Address", "Firmware", "Channel", "Camera Name", "Enabled", "Res Stream 1", "FPS Stream 1", "Status Stream 1", "Res Stream 2", "FPS Stream 2", "Status Stream 2")

foreach ($col in $columnNames) {
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $col
    $cb.Location = New-Object System.Drawing.Point(20, $yOffset)
    $cb.AutoSize = $true
    $cb.Checked = $true
    $group.Controls.Add($cb)
    $checkboxes[$col] = $cb
    $yOffset += 26
}

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(20, 650)
$lblStatus.Size = New-Object System.Drawing.Size(400, 20)
$lblStatus.ForeColor = [System.Drawing.Color]::SkyBlue
$lblStatus.Text = "Ready..."
$form.Controls.Add($lblStatus)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 675)
$progressBar.Size = New-Object System.Drawing.Size(400, 15)
$progressBar.Style = 'Blocks'
$form.Controls.Add($progressBar)

$lblGenerate = New-Object System.Windows.Forms.Label
$lblGenerate.Text = "Generate Reports:"
$lblGenerate.Location = New-Object System.Drawing.Point(20, 715)
$lblGenerate.AutoSize = $true
$lblGenerate.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($lblGenerate)

$btnCSV = New-Object System.Windows.Forms.Button
$btnCSV.Text = ".csv"
$btnCSV.Location = New-Object System.Drawing.Point(170, 705)
$btnCSV.Size = New-Object System.Drawing.Size(100, 40)
$btnCSV.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$btnCSV.ForeColor = [System.Drawing.Color]::White
$btnCSV.FlatStyle = 'Flat'
$form.Controls.Add($btnCSV)

$btnTXT = New-Object System.Windows.Forms.Button
$btnTXT.Text = ".txt"
$btnTXT.Location = New-Object System.Drawing.Point(280, 705)
$btnTXT.Size = New-Object System.Drawing.Size(100, 40)
$btnTXT.BackColor = [System.Drawing.Color]::FromArgb(34, 139, 34)
$btnTXT.ForeColor = [System.Drawing.Color]::White
$btnTXT.FlatStyle = 'Flat'
$form.Controls.Add($btnTXT)

# --- 5. LÓGICA DE LOS BOTONES ---
$btnInstall.Add_Click({
    if ($neededPSTools -ne "Latest" -and $neededPSTools -ne "Unknown" -and $xpVersion -ne "Unknown") {
        $msg = "Your XProtect version ($xpVersion) is not compatible with the most recent PSTools available.`nThe version you need is: $($neededPSTools).`n`nPlease check https://milestonepstools.com/help/compatibility/ to find the correct download package."
        [System.Windows.Forms.MessageBox]::Show($msg, "Compatibility Error", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $lblStatus.Text = "Downloading and installing MilestonePSTools... Please wait."
    $lblStatus.ForeColor = [System.Drawing.Color]::Orange
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        Set-ExecutionPolicy RemoteSigned -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex (irm 'https://www.milestonepstools.com/install.ps1')
        
        $newModule = Get-Module -Name MilestonePSTools -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        $newVer = if ($newModule) { $newModule.Version.ToString() } else { "Installed" }
        $lblVersions.Text = "Installed PSTools: $newVer`nXProtect Local Version: $xpVersion"

        $lblStatus.Text = "Installation successful! You can now connect."
        $lblStatus.ForeColor = [System.Drawing.Color]::LightGreen
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Installation Error", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
        $lblStatus.Text = "Installation failed."
        $lblStatus.ForeColor = [System.Drawing.Color]::Red
    }
})

$btnConnect.Add_Click({
    $noticeMsg = "The application will securely load the Milestone login prompt.`n`n(The app will safely remain active in your taskbar during authentication)."
    [System.Windows.Forms.MessageBox]::Show($noticeMsg, "Connecting to Milestone API", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    
    $form.DialogResult = [System.Windows.Forms.DialogResult]::Retry
})


# --- 6. FUNCIÓN DE EXTRACCIÓN ---
function Generate-Report {
    param ([string]$FormatType)

    $serverName = $cboServer.Text.Trim()
    
    if ([string]::IsNullOrEmpty($serverName) -or $serverName -eq "enter here your RS Hostname or FQDN...") {
        [System.Windows.Forms.MessageBox]::Show("Please enter or select a valid Recording Server Hostname or FQDN.", "Notice", 0, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $btnCSV.Enabled = $false
    $btnTXT.Enabled = $false
    $progressBar.Value = 0
    [System.Windows.Forms.Application]::DoEvents()

    try {
        if (-not (Get-VmsSite -ErrorAction SilentlyContinue)) {
            throw "You are not connected to a Milestone VMS. Use 'Connect to Management Server' to login."
        }

        $lblStatus.Text = "Connecting to $serverName..."
        $lblStatus.ForeColor = [System.Drawing.Color]::Orange
        [System.Windows.Forms.Application]::DoEvents()

        $rs = Get-VmsRecordingServer -Name $serverName -ErrorAction Stop
        
        $lblStatus.Text = "Mapping Hardware inventory... Please wait."
        
        $hardwares = Get-VmsHardware -RecordingServer $rs
        $detailedReport = @()
        $totalHw = $hardwares.Count
        $hwCounter = 0

        foreach ($hw in $hardwares) {
            $hwCounter++
            
            $pct = [math]::Min(100, [math]::Max(0, [math]::Round(($hwCounter / $totalHw) * 100)))
            $progressBar.Value = $pct
            
            $lblStatus.Text = "Processing Hardware $hwCounter of $($totalHw): $($hw.Name)..."
            [System.Windows.Forms.Application]::DoEvents()

            if ($cbIgnoreDisabled.Checked -and $hw.Enabled -eq $false) { continue }

            $hwSettings = $hw | Get-HardwareSetting -ErrorAction SilentlyContinue
            $firmware = "N/A"
            $mac = "N/A"
            
            if ($null -ne $hwSettings) {
                if ($hwSettings.FirmwareVersion) { $firmware = $hwSettings.FirmwareVersion }
                elseif ($hwSettings.Firmware) { $firmware = $hwSettings.Firmware }
                
                if ($hwSettings.MacAddress) { $mac = $hwSettings.MacAddress }
                elseif ($hwSettings.MAC) { $mac = $hwSettings.MAC }
            }

            if ($mac -eq "N/A" -and $hw.MacAddress) { $mac = $hw.MacAddress }
            $ip = if ($hw.Address) { $hw.Address } else { "N/A" }

            $cameras = $hw | Get-VmsCamera
            
            foreach ($camera in $cameras) {
                if ($cbIgnoreDisabled.Checked -and $camera.Enabled -eq $false) { continue }

                $allStreamsInfo = @($camera | Get-VmsDeviceStreamSetting -ErrorAction SilentlyContinue | Select-Object -First 2)
                $res1 = "N/A"; $fps1 = "N/A"
                $res2 = "N/A"; $fps2 = "N/A"
                
                if ($allStreamsInfo.Count -gt 0 -and $null -ne $allStreamsInfo[0].Settings) {
                    $s1 = $allStreamsInfo[0].Settings
                    if ($s1["Resolution"]) { $res1 = $s1["Resolution"] } elseif ($s1.Resolution) { $res1 = $s1.Resolution }
                    if ($s1["FPS"]) { $fps1 = $s1["FPS"] } elseif ($s1.FPS) { $fps1 = $s1.FPS } elseif ($s1["FramesPerSecond"]) { $fps1 = $s1["FramesPerSecond"] } elseif ($s1["Frames per second"]) { $fps1 = $s1["Frames per second"] } elseif ($s1["Framerate"]) { $fps1 = $s1["Framerate"] }
                }
                
                if ($allStreamsInfo.Count -gt 1 -and $null -ne $allStreamsInfo[1].Settings) {
                    $s2 = $allStreamsInfo[1].Settings
                    if ($s2["Resolution"]) { $res2 = $s2["Resolution"] } elseif ($s2.Resolution) { $res2 = $s2.Resolution }
                    if ($s2["FPS"]) { $fps2 = $s2["FPS"] } elseif ($s2.FPS) { $fps2 = $s2.FPS } elseif ($s2["FramesPerSecond"]) { $fps2 = $s2["FramesPerSecond"] } elseif ($s2["Frames per second"]) { $fps2 = $s2["Frames per second"] } elseif ($s2["Framerate"]) { $fps2 = $s2["Framerate"] }
                }
                
                $streamsTab = @($camera | Get-VmsCameraStream -ErrorAction SilentlyContinue | Select-Object -First 2)
                $statusStream1 = "N/A"; $statusStream2 = "N/A"
                
                if ($streamsTab.Count -gt 0) {
                    if ($null -ne $streamsTab[0]) {
                        $tags1 = @()
                        if ($streamsTab[0].LiveMode -match 'Always') { $tags1 += 'Live' }
                        if ($streamsTab[0].Recording -match 'Primary') { $tags1 += 'Recording' }
                        $statusStream1 = if ($tags1.Count -gt 0) { $tags1 -join ' & ' } else { 'Recording' }
                    }
                    if ($streamsTab.Count -gt 1 -and $null -ne $streamsTab[1]) {
                        $tags2 = @()
                        if ($streamsTab[1].LiveMode -match 'Always') { $tags2 += 'Live' }
                        if ($streamsTab[1].Recording -match 'Primary') { $tags2 += 'Recording' }
                        $statusStream2 = if ($tags2.Count -gt 0) { $tags2 -join ' & ' } else { 'Recording' }
                    }
                }

                $camObj = [PSCustomObject]@{
                    RecordingServer   = $serverName
                    Hardware          = $hw.Name
                    'IP Address'      = $ip
                    'MAC Address'     = $mac
                    Firmware          = $firmware
                    Channel           = $camera.Channel
                    'Camera Name'     = $camera.Name
                    Enabled           = $camera.Enabled
                    'Res Stream 1'    = $res1
                    'FPS Stream 1'    = $fps1
                    'Status Stream 1' = $statusStream1
                    'Res Stream 2'    = $res2
                    'FPS Stream 2'    = $fps2
                    'Status Stream 2' = $statusStream2
                }
                $detailedReport += $camObj
            }
        }

        $selectedColumns = @()
        foreach ($col in $columnNames) {
            if ($checkboxes[$col].Checked) { $selectedColumns += $col }
        }

        if ($selectedColumns.Count -gt 0) {
            
            $outputDir = "C:\temp"
            if (-not (Test-Path -Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }

            $baseFileName = "Milestone_Export_$($serverName.Replace('.','_'))"
            $ext = if ($FormatType -eq "CSV") { ".csv" } else { ".txt" }
            
            $OutputPath = Join-Path -Path $outputDir -ChildPath "$baseFileName$ext"
            $counter = 1
            while (Test-Path -Path $OutputPath) {
                $OutputPath = Join-Path -Path $outputDir -ChildPath "$baseFileName($counter)$ext"
                $counter++
            }

            if ($FormatType -eq "CSV") {
                $detailedReport | Select-Object $selectedColumns | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            } else {
                $detailedReport | Select-Object $selectedColumns | Format-Table -AutoSize | Out-File -FilePath $OutputPath -Encoding UTF8 -Width 4000
            }

            $lblStatus.Text = "✨ Success! $FormatType Report saved at C:\temp"
            $lblStatus.ForeColor = [System.Drawing.Color]::LightGreen
            $progressBar.Value = 100
            Invoke-Item $OutputPath
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select at least one column.", "Notice", 0, [System.Windows.Forms.MessageBoxIcon]::Information)
            $lblStatus.Text = "Ready..."
            $lblStatus.ForeColor = [System.Drawing.Color]::SkyBlue
            $progressBar.Value = 0
        }

    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Execution Error", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
        $lblStatus.Text = "Error occurred. Check popup."
        $lblStatus.ForeColor = [System.Drawing.Color]::Red
        $progressBar.Value = 0
    } finally {
        $btnCSV.Enabled = $true
        $btnTXT.Enabled = $true
    }
}

$btnCSV.Add_Click({ Generate-Report -FormatType "CSV" })
$btnTXT.Add_Click({ Generate-Report -FormatType "TXT" })

# --- 7. GESTOR DE VENTANAS (LOOP BREAK ARCHITECTURE & DUMMY FORM) ---
$runApp = $true

while ($runApp) {
    $dialogResult = $form.ShowDialog()
    
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Retry) {
        
        # EL TRUCO NINJA: Formulario fantasma para sostener el icono en la barra de tareas
        $dummy = New-Object System.Windows.Forms.Form
        $dummy.Text = "XProtect Report Builder - Authenticating..."
        $dummy.Icon = $form.Icon
        $dummy.ShowInTaskbar = $true
        $dummy.WindowState = 'Minimized'
        $dummy.Show()

        try {
            if ($cbForceLogin.Checked) {
                Connect-ManagementServer -ShowDialog -AcceptEula -Force -DisableAutoLogin | Out-Null
            } else {
                Connect-ManagementServer -ShowDialog -AcceptEula -Force | Out-Null
            }
            
            # --- POBLACIÓN DE SERVIDORES CON MATRIZ FORZADA PARA EL COMBOBOX ---
            if (Get-VmsSite -ErrorAction SilentlyContinue) {
                # Forzamos la consulta a ser un arreglo @() para evitar iteraciones nulas
                $rsList = @(Get-VmsRecordingServer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
                if ($rsList.Count -gt 0) {
                    $cboServer.Items.Clear()
                    foreach ($rsName in $rsList) {
                        [void]$cboServer.Items.Add($rsName)
                    }
                    # Seleccionamos automáticamente el primer servidor de la lista
                    $cboServer.Text = $cboServer.Items[0]
                }
            }

            $lblStatus.Text = "Connected securely to Management Server!"
            $lblStatus.ForeColor = [System.Drawing.Color]::LightGreen
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Login was cancelled or failed: " + $_.Exception.Message, "Connection Alert", 0, [System.Windows.Forms.MessageBoxIcon]::Warning)
            $lblStatus.Text = "Connection aborted or cancelled."
            $lblStatus.ForeColor = [System.Drawing.Color]::Orange
        } finally {
            # Destruimos el fantasma; la ventana principal reaparece instantáneamente
            $dummy.Dispose()
        }
    } else {
        $runApp = $false
    }
}