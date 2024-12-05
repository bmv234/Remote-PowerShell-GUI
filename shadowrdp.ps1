# Shadow RDP Management GUI Tool for IT Staff
# Requires Domain Admin credentials and proper permissions
# Compatible with PowerShell 5.1 and above

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module ActiveDirectory

# Configuration settings
$script:Config = @{
    MaxThreads = 100
    PingTimeout = 1000
    RefreshInterval = 300  # 5 minutes
    LogFile = "shadowrdp.log"
}

# Load saved settings if they exist
function Load-Settings {
    $settingsPath = Join-Path $PSScriptRoot "settings.json"
    if (Test-Path $settingsPath) {
        try {
            $savedSettings = Get-Content $settingsPath | ConvertFrom-Json
            $script:Config.MaxThreads = $savedSettings.MaxThreads
            $script:Config.PingTimeout = $savedSettings.PingTimeout
            $script:Config.RefreshInterval = $savedSettings.RefreshInterval
            return $true
        }
        catch {
            return $false
        }
    }
    return $false
}

# Save current settings
function Save-Settings {
    $settingsPath = Join-Path $PSScriptRoot "settings.json"
    $script:Config | ConvertTo-Json | Set-Content $settingsPath
}

# Function to get online hosts in the domain with improved error handling and logging
function Global:Get-OnlineHosts {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$LogTextBox,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListBox]$ListBox
    )
    
    Log-Message -Message "Starting parallel ping host discovery process..." -LogTextBox $LogTextBox
    try {
        Log-Message -Message "Retrieving computers from Active Directory..." -LogTextBox $LogTextBox
        $allHosts = Get-ADComputer -Filter * -Properties Name, DNSHostName, OperatingSystem, LastLogonDate | 
                   Where-Object { $_.Enabled -eq $true } |
                   Sort-Object Name
        
        if ($null -eq $allHosts -or $allHosts.Count -eq 0) {
            throw "No computers found in Active Directory. Please check your AD connection and permissions."
        }
        
        Log-Message -Message "Found $($allHosts.Count) enabled computers in AD." -LogTextBox $LogTextBox
        
        # Create runspace pool with improved error handling
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $script:Config.MaxThreads)
        $runspacePool.Open()

        $scriptBlock = {
            param($computer, $timeoutMilliseconds)
            $pingTarget = if ([string]::IsNullOrEmpty($computer.DNSHostName)) { $computer.Name } else { $computer.DNSHostName }
            $ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $reply = $ping.Send($pingTarget, $timeoutMilliseconds)
                if ($reply.Status -eq 'Success') {
                    return @{
                        Name = $computer.Name
                        DNSHostName = $computer.DNSHostName
                        IPAddress = $reply.Address.ToString()
                        OS = $computer.OperatingSystem
                        LastLogon = $computer.LastLogonDate
                        ResponseTime = $reply.RoundtripTime
                    }
                }
            }
            catch {
                # Ping failed, computer is likely offline
            }
            finally {
                $ping.Dispose()
            }
            return $null
        }

        # Create and invoke runspaces with progress tracking
        $runspaces = @()
        foreach ($computer in $allHosts) {
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($script:Config.PingTimeout)
            $runspace.RunspacePool = $runspacePool
            $runspaces += [PSCustomObject]@{ 
                Pipe = $runspace
                Status = $runspace.BeginInvoke()
                Computer = $computer.Name
            }
        }

        # Process results with improved display
        $onlineHosts = @()
        $processedCount = 0
        foreach ($runspace in $runspaces) {
            $result = $runspace.Pipe.EndInvoke($runspace.Status)
            if ($result) {
                $onlineHosts += $result
                $displayText = "{0} ({1}) - {2} - Response: {3}ms" -f $result.Name, $result.IPAddress, $result.OS, $result.ResponseTime
                $ListBox.Invoke([Action]{$ListBox.Items.Add($displayText)})
                Log-Message -Message "$($result.Name) ($($result.IPAddress)) is online - OS: $($result.OS)" -LogTextBox $LogTextBox
            }
            $runspace.Pipe.Dispose()
            $processedCount++
            
            # Update progress every 10 hosts or for the last host
            if ($processedCount % 10 -eq 0 -or $processedCount -eq $allHosts.Count) {
                $percentComplete = [math]::Round(($processedCount / $allHosts.Count) * 100, 2)
                Log-Message -Message "Progress: $percentComplete% ($processedCount/$($allHosts.Count))" -LogTextBox $LogTextBox
            }
        }

        # Clean up
        $runspacePool.Close()
        $runspacePool.Dispose()

        Log-Message -Message "Scan complete. Found $($onlineHosts.Count) online hosts." -LogTextBox $LogTextBox
        return $onlineHosts
    }
    catch {
        Log-Message -Message ("Error in Get-OnlineHosts: {0}" -f $_.Exception.Message) -LogTextBox $LogTextBox
        Log-Message -Message ("Stack Trace: {0}" -f $_.ScriptStackTrace) -LogTextBox $LogTextBox
        return @()
    }
}

# Function to get active sessions on a host with improved monitoring
function Global:Get-ActiveSessions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$LogTextBox
    )
    Log-Message -Message "Retrieving active sessions for $ComputerName..." -LogTextBox $LogTextBox
    
    try {
        $qwinstaOutput = qwinsta /server:$ComputerName 2>&1
        if ($qwinstaOutput -is [System.Management.Automation.ErrorRecord]) {
            throw $qwinstaOutput
        }

        # Debug logging
        Log-Message -Message "Raw qwinsta output:" -LogTextBox $LogTextBox
        $qwinstaOutput | ForEach-Object { Log-Message -Message $_ -LogTextBox $LogTextBox }

        $sessions = @()
        
        # Process each line after the header
        $qwinstaOutput | Select-Object -Skip 1 | ForEach-Object {
            $line = $_.Trim()
            Log-Message -Message "Processing line: $line" -LogTextBox $LogTextBox

            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) {
                return
            }

            # Split the line into tokens and remove empty entries
            $tokens = $line -split '\s+' | Where-Object { $_ }
            Log-Message -Message "Tokens: $($tokens -join ', ')" -LogTextBox $LogTextBox

            # Check if this is an active session
            if ($tokens -contains "Active") {
                try {
                    # Find the session ID (should be a number)
                    $sessionId = $tokens | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
                    if ($sessionId) {
                        # Get the index of the session ID to help determine username
                        $idIndex = [array]::IndexOf($tokens, $sessionId)
                        
                        # The session name is always the first token
                        $sessionName = $tokens[0]
                        
                        # Username is typically before the session ID, unless it's a console session
                        $username = if ($idIndex -gt 1) { $tokens[1] } else { $sessionName }
                        
                        # Find session type (rdp, console, etc.)
                        $type = $tokens | Where-Object { $_ -match 'rdp|console' } | Select-Object -First 1
                        if (-not $type) { $type = "Unknown" }

                        Log-Message -Message "Found active session - Name: $sessionName, User: $username, ID: $sessionId, Type: $type" -LogTextBox $LogTextBox

                        $session = @{
                            SessionName = $sessionName
                            Username = $username
                            ID = $sessionId
                            State = "Active"
                            Type = $type
                            StartTime = Get-SessionStartTime -ComputerName $ComputerName -SessionID $sessionId
                            ComputerName = $ComputerName
                        }

                        $sessions += $session
                        Log-Message -Message "Added active session: ID=$($session.ID), User=$($session.Username), Type=$($session.Type)" -LogTextBox $LogTextBox
                    }
                    else {
                        Log-Message -Message "No valid session ID found in line" -LogTextBox $LogTextBox
                    }
                }
                catch {
                    Log-Message -Message "Error parsing active session line: $($_.Exception.Message)" -LogTextBox $LogTextBox
                }
            }
            else {
                Log-Message -Message "Skipping non-active session" -LogTextBox $LogTextBox
            }
        }

        Log-Message -Message "Found $($sessions.Count) active sessions on $ComputerName." -LogTextBox $LogTextBox
        return $sessions
    }
    catch {
        $errorMessage = $_.Exception.Message
        Log-Message -Message "Error retrieving sessions for $ComputerName." -LogTextBox $LogTextBox
        Log-Message -Message "Error details: $errorMessage" -LogTextBox $logTextBox
        return @()
    }
}

# New function to get session start time
function Get-SessionStartTime {
    param (
        [string]$ComputerName,
        [string]$SessionID
    )
    try {
        $query = "Select * from Win32_Session Where SessionId = '$SessionID'"
        $session = Get-WmiObject -Query $query -ComputerName $ComputerName -ErrorAction Stop
        return $session.StartTime
    }
    catch {
        return $null
    }
}

# Function to initiate shadow RDP session with enhanced monitoring
function Global:Start-ShadowRDP {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [string]$SessionID,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$LogTextBox
    )
    Log-Message -Message "Initiating shadow RDP session to $ComputerName, Session ID: $SessionID" -LogTextBox $LogTextBox
    
    try {
        # Enhanced session state verification
        $sessionInfo = qwinsta /server:$ComputerName | Where-Object { $_ -match "^\s*\S+\s+\S+\s+$SessionID\s+" }
        if ($null -eq $sessionInfo) {
            throw "Session ID $SessionID not found on $ComputerName."
        }

        $sessionState = if ($sessionInfo -match 'Active') { 'Active' } elseif ($sessionInfo -match 'Disc') { 'Disconnected' } else { 'Unknown' }

        if ($sessionState -ne 'Active') {
            throw "The specified session (ID: $SessionID) is not in an Active state. Current state: $sessionState"
        }

        # Construct the mstsc command for shadow mode
        $mstscArguments = "/v:$ComputerName /shadow:$SessionID /control /noConsentPrompt"
        
        # Start the mstsc process
        $process = Start-Process -FilePath "mstsc.exe" -ArgumentList $mstscArguments -PassThru
        
        if ($null -eq $process) {
            throw "Failed to start mstsc.exe process"
        }
        
        Log-Message -Message "Shadow RDP session initiated. Process ID: $($process.Id)" -LogTextBox $LogTextBox
        
        # Monitor process startup
        Start-Sleep -Seconds 2
        if ($process.HasExited) {
            throw "mstsc.exe process exited immediately. Exit Code: $($process.ExitCode)"
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "Shadow RDP session to $ComputerName (Session ID: $SessionID) has been initiated.`nProcess ID: $($process.Id)",
            "Shadow RDP",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        $errorMessage = $_.Exception.Message
        Log-Message -Message "Error starting shadow RDP session: $errorMessage" -LogTextBox $LogTextBox
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to start shadow RDP session: $errorMessage",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

# Enhanced logging function with file output
function Global:Log-Message {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$LogTextBox
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    # Append to GUI
    $LogTextBox.Invoke([Action]{
        $LogTextBox.AppendText("$logMessage`r`n")
        $LogTextBox.ScrollToCaret()
    })
    
    # Append to log file
    $logFilePath = Join-Path $PSScriptRoot $script:Config.LogFile
    Add-Content -Path $logFilePath -Value $logMessage
    
    [System.Windows.Forms.Application]::DoEvents()
}

# Create the main form with improved styling
$form = New-Object System.Windows.Forms.Form
$form.Text = "Shadow RDP Management Tool"
$form.Size = New-Object System.Drawing.Size(1200,700)  # Increased width for side-by-side layout
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(240,240,240)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Left side - Hosts
$searchBoxHosts = New-Object System.Windows.Forms.TextBox
$searchBoxHosts.Location = New-Object System.Drawing.Point(10,10)
$searchBoxHosts.Size = New-Object System.Drawing.Size(200,23)
$searchBoxHosts.Text = "Search hosts..."
$searchBoxHosts.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($searchBoxHosts)

$listBoxHosts = New-Object System.Windows.Forms.ListBox
$listBoxHosts.Location = New-Object System.Drawing.Point(10,40)
$listBoxHosts.Size = New-Object System.Drawing.Size(580,350)
$listBoxHosts.Font = New-Object System.Drawing.Font("Consolas", 9)
$listBoxHosts.BackColor = [System.Drawing.Color]::White
$listBoxHosts.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($listBoxHosts)

# Right side - Sessions
$searchBoxSessions = New-Object System.Windows.Forms.TextBox
$searchBoxSessions.Location = New-Object System.Drawing.Point(610,10)
$searchBoxSessions.Size = New-Object System.Drawing.Size(200,23)
$searchBoxSessions.Text = "Search sessions..."
$searchBoxSessions.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($searchBoxSessions)

$listBoxSessions = New-Object System.Windows.Forms.ListBox
$listBoxSessions.Location = New-Object System.Drawing.Point(610,40)
$listBoxSessions.Size = New-Object System.Drawing.Size(580,350)
$listBoxSessions.Font = New-Object System.Drawing.Font("Consolas", 9)
$listBoxSessions.BackColor = [System.Drawing.Color]::White
$listBoxSessions.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($listBoxSessions)

# Buttons
$buttonRefresh = New-Object System.Windows.Forms.Button
$buttonRefresh.Location = New-Object System.Drawing.Point(10,400)
$buttonRefresh.Size = New-Object System.Drawing.Size(100,30)
$buttonRefresh.Text = "Refresh"
$buttonRefresh.BackColor = [System.Drawing.Color]::FromArgb(0,122,204)
$buttonRefresh.ForeColor = [System.Drawing.Color]::White
$buttonRefresh.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$form.Controls.Add($buttonRefresh)

$buttonStartShadow = New-Object System.Windows.Forms.Button
$buttonStartShadow.Location = New-Object System.Drawing.Point(120,400)
$buttonStartShadow.Size = New-Object System.Drawing.Size(120,30)
$buttonStartShadow.Text = "Start Shadow RDP"
$buttonStartShadow.BackColor = [System.Drawing.Color]::FromArgb(0,122,204)
$buttonStartShadow.ForeColor = [System.Drawing.Color]::White
$buttonStartShadow.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$form.Controls.Add($buttonStartShadow)

# Log box at the bottom
$logTextBox = New-Object System.Windows.Forms.TextBox
$logTextBox.Location = New-Object System.Drawing.Point(10,440)
$logTextBox.Size = New-Object System.Drawing.Size(1180,210)
$logTextBox.Multiline = $true
$logTextBox.ScrollBars = "Vertical"
$logTextBox.ReadOnly = $true
$logTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logTextBox.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$logTextBox.ForeColor = [System.Drawing.Color]::FromArgb(200,200,200)
$form.Controls.Add($logTextBox)

# Host search functionality
$searchBoxHosts.Add_GotFocus({
    if ($this.Text -eq "Search hosts..." -and $this.ForeColor -eq [System.Drawing.Color]::Gray) {
        $this.Text = ""
        $this.ForeColor = [System.Drawing.Color]::Black
    }
})

$searchBoxHosts.Add_LostFocus({
    if ($this.Text -eq "") {
        $this.Text = "Search hosts..."
        $this.ForeColor = [System.Drawing.Color]::Gray
    }
})

$searchBoxHosts.Add_TextChanged({
    if ($this.ForeColor -eq [System.Drawing.Color]::Black) {  # Only search if not showing watermark
        $searchText = $this.Text.ToLower()
        $listBoxHosts.BeginUpdate()
        $listBoxHosts.Items.Clear()
        
        $script:originalItems | Where-Object { $_.ToLower().Contains($searchText) } | ForEach-Object {
            $listBoxHosts.Items.Add($_)
        }
        
        $listBoxHosts.EndUpdate()
    }
})

# Session search functionality
$searchBoxSessions.Add_GotFocus({
    if ($this.Text -eq "Search sessions..." -and $this.ForeColor -eq [System.Drawing.Color]::Gray) {
        $this.Text = ""
        $this.ForeColor = [System.Drawing.Color]::Black
    }
})

$searchBoxSessions.Add_LostFocus({
    if ($this.Text -eq "") {
        $this.Text = "Search sessions..."
        $this.ForeColor = [System.Drawing.Color]::Gray
    }
})

$searchBoxSessions.Add_TextChanged({
    if ($this.ForeColor -eq [System.Drawing.Color]::Black) {  # Only search if not showing watermark
        $searchText = $this.Text.ToLower()
        $listBoxSessions.BeginUpdate()
        $listBoxSessions.Items.Clear()
        
        $script:originalSessionItems | Where-Object { $_.ToLower().Contains($searchText) } | ForEach-Object {
            $listBoxSessions.Items.Add($_)
        }
        
        $listBoxSessions.EndUpdate()
    }
})

# Event handler for the Refresh button - now with parallel session retrieval
$buttonRefresh.Add_Click({
    $listBoxHosts.Items.Clear()
    $listBoxSessions.Items.Clear()
    Log-Message -Message "Starting refresh of hosts and sessions..." -LogTextBox $logTextBox
    
    # Get online hosts
    $onlineHosts = Get-OnlineHosts -LogTextBox $logTextBox -ListBox $listBoxHosts
    
    # Store hosts for search functionality
    $script:originalItems = @($listBoxHosts.Items)
    
    # Create runspace pool for parallel session retrieval
    $sessionRunspacePool = [runspacefactory]::CreateRunspacePool(1, $script:Config.MaxThreads)
    $sessionRunspacePool.Open()
    
    $sessionRunspaces = @()
    
    # Create runspaces for each online host
    foreach ($hostItem in $listBoxHosts.Items) {
        $computerName = ($hostItem -split ' ')[0]
        
        $scriptBlock = {
            param($computerName)
            
            try {
                $qwinstaOutput = qwinsta /server:$computerName 2>&1
                if ($qwinstaOutput -is [System.Management.Automation.ErrorRecord]) {
                    return @()
                }

                $sessions = @()
                
                $qwinstaOutput | Select-Object -Skip 1 | ForEach-Object {
                    $line = $_.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        $tokens = $line -split '\s+' | Where-Object { $_ }
                        
                        if ($tokens -contains "Active") {
                            $sessionId = $tokens | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
                            if ($sessionId) {
                                $idIndex = [array]::IndexOf($tokens, $sessionId)
                                $sessionName = $tokens[0]
                                $username = if ($idIndex -gt 1) { $tokens[1] } else { $sessionName }
                                $type = $tokens | Where-Object { $_ -match 'rdp|console' } | Select-Object -First 1
                                if (-not $type) { $type = "Unknown" }

                                try {
                                    $query = "Select * from Win32_Session Where SessionId = '$SessionID'"
                                    $wmiSession = Get-WmiObject -Query $query -ComputerName $computerName -ErrorAction Stop
                                    $startTime = $wmiSession.StartTime
                                }
                                catch {
                                    $startTime = $null
                                }

                                $sessions += @{
                                    ComputerName = $computerName
                                    SessionName = $sessionName
                                    Username = $username
                                    ID = $sessionId
                                    State = "Active"
                                    Type = $type
                                    StartTime = $startTime
                                }
                            }
                        }
                    }
                }
                return $sessions
            }
            catch {
                return @()
            }
        }
        
        $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($computerName)
        $runspace.RunspacePool = $sessionRunspacePool
        
        $sessionRunspaces += [PSCustomObject]@{
            Pipe = $runspace
            Status = $runspace.BeginInvoke()
            Computer = $computerName
        }
    }
    
    # Process results
    foreach ($runspace in $sessionRunspaces) {
        $sessions = $runspace.Pipe.EndInvoke($runspace.Status)
        foreach ($session in $sessions) {
            $sessionStartTime = if ($session.StartTime) {
                Get-Date $session.StartTime -Format "yyyy-MM-dd HH:mm:ss"
            } else {
                "Unknown"
            }
            $displayText = "$($session.ComputerName) - ID: $($session.ID), User: $($session.Username), Type: $($session.Type), Started: $sessionStartTime"
            $listBoxSessions.Items.Add($displayText)
            Log-Message -Message "Added session to list: $displayText" -LogTextBox $logTextBox
        }
        $runspace.Pipe.Dispose()
    }
    
    # Clean up
    $sessionRunspacePool.Close()
    $sessionRunspacePool.Dispose()
    
    # Store sessions for search functionality
    $script:originalSessionItems = @($listBoxSessions.Items)
    
    Log-Message -Message "Refresh complete. Found $($listBoxHosts.Items.Count) hosts and $($listBoxSessions.Items.Count) active sessions." -LogTextBox $logTextBox
})

# Event handler for the Start Shadow button
$buttonStartShadow.Add_Click({
    $selectedSession = $listBoxSessions.SelectedItem
    if ($selectedSession) {
        # Extract computer name and session ID from the session display text
        if ($selectedSession -match '^(\S+)\s+-\s+ID:\s*(\d+)') {
            $computerName = $matches[1]
            $sessionId = $matches[2]
            Log-Message -Message "Selected computer: $computerName, Session ID: $sessionId" -LogTextBox $logTextBox
            Start-ShadowRDP -ComputerName $computerName -SessionID $sessionId -LogTextBox $logTextBox
        } else {
            Log-Message -Message "Error: Could not extract computer name and session ID from: $selectedSession" -LogTextBox $logTextBox
            [System.Windows.Forms.MessageBox]::Show(
                "Could not extract session information.`nSelected session: $selectedSession",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    } else {
        Log-Message -Message "Error: No session selected." -LogTextBox $logTextBox
        [System.Windows.Forms.MessageBox]::Show("Please select a session to shadow.", "Error")
    }
})

# Load settings
Load-Settings

# Initial refresh
$buttonRefresh.PerformClick()

# Show the form
$form.ShowDialog()
