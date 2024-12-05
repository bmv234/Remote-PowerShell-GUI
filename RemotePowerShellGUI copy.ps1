# Remote PowerShell GUI Management Tool
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module ActiveDirectory

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Remote PowerShell Management"
$form.Size = New-Object System.Drawing.Size(1000,700)
$form.StartPosition = "CenterScreen"

# Domain Scanner Section
$scanGroupBox = New-Object System.Windows.Forms.GroupBox
$scanGroupBox.Location = New-Object System.Drawing.Point(10,10)
$scanGroupBox.Size = New-Object System.Drawing.Size(300,600)
$scanGroupBox.Text = "Domain Scanner"
$form.Controls.Add($scanGroupBox)

# Computer List
$computerList = New-Object System.Windows.Forms.ListView
$computerList.Location = New-Object System.Drawing.Point(10,60)
$computerList.Size = New-Object System.Drawing.Size(280,520)
$computerList.View = [System.Windows.Forms.View]::Details
$computerList.FullRowSelect = $true
$computerList.GridLines = $true
$computerList.Parent = $scanGroupBox

# Add columns
$computerList.Columns.Add("Computer Name", 120)
$computerList.Columns.Add("IP Address", 100)
$computerList.Columns.Add("OS", 150)

# Function to get OS information
function Get-RemoteOS {
    param([string]$ComputerName)
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        return "$($os.Caption) $($os.Version)"
    }
    catch {
        return "Windows (Query Failed)"
    }
}

# Function to safely update ListView from any thread
function Update-ListView {
    param(
        [System.Windows.Forms.ListView]$ListView,
        [string]$ComputerName,
        [string]$IPAddress,
        [string]$OS
    )
    
    if ($ListView.InvokeRequired) {
        $ListView.Invoke(
            [Action[string,string,string]]{
                param($name, $ip, $os)
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                $item.SubItems.Add($ip)
                $item.SubItems.Add($os)
                $ListView.Items.Add($item)
            }, $ComputerName, $IPAddress, $OS)
    } else {
        $item = New-Object System.Windows.Forms.ListViewItem($ComputerName)
        $item.SubItems.Add($IPAddress)
        $item.SubItems.Add($OS)
        $ListView.Items.Add($item)
    }
}

# Function to safely update TextBox from any thread
function Write-Log {
    param(
        [System.Windows.Forms.TextBox]$TextBox,
        [string]$Message
    )
    
    if ($TextBox.InvokeRequired) {
        $TextBox.Invoke([Action[string]]{ 
            param($msg)
            $TextBox.AppendText("$msg`r`n")
            $TextBox.ScrollToCaret()
        }, $Message)
    } else {
        $TextBox.AppendText("$Message`r`n")
        $TextBox.ScrollToCaret()
    }
}

# Function to safely clear ListView from any thread
function Clear-ListView {
    param([System.Windows.Forms.ListView]$ListView)
    
    if ($ListView.InvokeRequired) {
        $ListView.Invoke([Action]{ $ListView.Items.Clear() })
    } else {
        $ListView.Items.Clear()
    }
}

# Function to get online hosts
function Get-OnlineHosts {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$LogTextBox
    )
    
    Clear-ListView -ListView $ListView
    Write-Log -TextBox $LogTextBox -Message "Starting parallel ping host discovery process..."
    
    try {
        Write-Log -TextBox $LogTextBox -Message "Retrieving computers from Active Directory..."
        $allHosts = Get-ADComputer -Filter * -Properties Name, DNSHostName | 
                   Where-Object { $_.Enabled -eq $true } |
                   Sort-Object Name
        
        if ($null -eq $allHosts -or $allHosts.Count -eq 0) {
            throw "No computers found in Active Directory."
        }
        
        Write-Log -TextBox $LogTextBox -Message "Found $($allHosts.Count) enabled computers in AD."
        
        # Create runspace pool
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, 100)
        $runspacePool.Open()

        $scriptBlock = {
            param($computer)
            $pingTarget = if ([string]::IsNullOrEmpty($computer.DNSHostName)) { $computer.Name } else { $computer.DNSHostName }
            $ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $reply = $ping.Send($pingTarget, 1000)
                if ($reply.Status -eq 'Success') {
                    # Get OS information
                    $os = try {
                        $wmi = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer.Name -ErrorAction Stop
                        "$($wmi.Caption) $($wmi.Version)"
                    }
                    catch {
                        "Windows (Query Failed)"
                    }
                    
                    return @{
                        Name = $computer.Name
                        IPAddress = $reply.Address.ToString()
                        OS = $os
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

        # Create and invoke runspaces
        $runspaces = @()
        foreach ($computer in $allHosts) {
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer)
            $runspace.RunspacePool = $runspacePool
            $runspaces += [PSCustomObject]@{ 
                Pipe = $runspace
                Status = $runspace.BeginInvoke()
            }
        }

        # Process results
        $onlineHosts = @()
        foreach ($runspace in $runspaces) {
            $result = $runspace.Pipe.EndInvoke($runspace.Status)
            if ($result) {
                $onlineHosts += $result
                Update-ListView -ListView $ListView -ComputerName $result.Name -IPAddress $result.IPAddress -OS $result.OS
                Write-Log -TextBox $LogTextBox -Message "$($result.Name) ($($result.IPAddress)) is online - OS: $($result.OS)"
            }
            $runspace.Pipe.Dispose()
        }

        # Clean up
        $runspacePool.Close()
        $runspacePool.Dispose()

        Write-Log -TextBox $LogTextBox -Message "Scan complete. Found $($onlineHosts.Count) online hosts."
        return $onlineHosts
    }
    catch {
        Write-Log -TextBox $LogTextBox -Message "Error in Get-OnlineHosts: $($_.Exception.Message)"
        return @()
    }
}

$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Location = New-Object System.Drawing.Point(10,20)
$scanButton.Size = New-Object System.Drawing.Size(280,30)
$scanButton.Text = "Scan Domain for Online Hosts"
$scanButton.Parent = $scanGroupBox
$scanButton.Add_Click({
    Get-OnlineHosts -ListView $computerList -LogTextBox $resultsTextBox
})

# Management Section
$managementGroupBox = New-Object System.Windows.Forms.GroupBox
$managementGroupBox.Location = New-Object System.Drawing.Point(320,10)
$managementGroupBox.Size = New-Object System.Drawing.Size(660,600)
$managementGroupBox.Text = "Computer Management"
$form.Controls.Add($managementGroupBox)

# Computer input section
$computerLabel = New-Object System.Windows.Forms.Label
$computerLabel.Location = New-Object System.Drawing.Point(10,20)
$computerLabel.Size = New-Object System.Drawing.Size(120,20)
$computerLabel.Text = "Computer Name:"
$computerLabel.Parent = $managementGroupBox

$computerTextBox = New-Object System.Windows.Forms.TextBox
$computerTextBox.Location = New-Object System.Drawing.Point(130,20)
$computerTextBox.Size = New-Object System.Drawing.Size(200,20)
$computerTextBox.Parent = $managementGroupBox

# Command input section
$commandLabel = New-Object System.Windows.Forms.Label
$commandLabel.Location = New-Object System.Drawing.Point(10,50)
$commandLabel.Size = New-Object System.Drawing.Size(120,20)
$commandLabel.Text = "PowerShell Command:"
$commandLabel.Parent = $managementGroupBox

$commandTextBox = New-Object System.Windows.Forms.TextBox
$commandTextBox.Location = New-Object System.Drawing.Point(130,50)
$commandTextBox.Size = New-Object System.Drawing.Size(400,20)
$commandTextBox.Parent = $managementGroupBox

# Run Command button
$runCommandButton = New-Object System.Windows.Forms.Button
$runCommandButton.Location = New-Object System.Drawing.Point(540,50)
$runCommandButton.Size = New-Object System.Drawing.Size(100,20)
$runCommandButton.Text = "Run Command"
$runCommandButton.Parent = $managementGroupBox
$runCommandButton.Add_Click({
    $computerName = $computerTextBox.Text
    $command = $commandTextBox.Text
    
    if ([string]::IsNullOrWhiteSpace($computerName) -or [string]::IsNullOrWhiteSpace($command)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter both computer name and command.", "Error")
        return
    }
    
    try {
        Write-Log -TextBox $resultsTextBox -Message "Connecting to $computerName..."
        $session = New-PSSession -ComputerName $computerName -ErrorAction Stop
        
        Write-Log -TextBox $resultsTextBox -Message "Executing command: $command"
        $result = Invoke-Command -Session $session -ScriptBlock ([ScriptBlock]::Create($command)) -ErrorAction Stop
        
        Write-Log -TextBox $resultsTextBox -Message "Command output:"
        $result | ForEach-Object { Write-Log -TextBox $resultsTextBox -Message $_ }
        
        Remove-PSSession -Session $session
        Write-Log -TextBox $resultsTextBox -Message "Disconnected from $computerName"
    }
    catch {
        Write-Log -TextBox $resultsTextBox -Message "Error: $_"
        [System.Windows.Forms.MessageBox]::Show("Error executing command: $_", "Error")
    }
})

# Connect button
$connectButton = New-Object System.Windows.Forms.Button
$connectButton.Location = New-Object System.Drawing.Point(340,20)
$connectButton.Size = New-Object System.Drawing.Size(100,20)
$connectButton.Text = "Connect"
$connectButton.Parent = $managementGroupBox
$connectButton.Add_Click({
    $computerName = $computerTextBox.Text
    try {
        $result = Test-WSMan -ComputerName $computerName -ErrorAction Stop
        [System.Windows.Forms.MessageBox]::Show("Successfully connected to $computerName", "Success")
        $statusLabel.Text = "Status: Connected to $computerName"
        $statusLabel.ForeColor = [System.Drawing.Color]::Green
        # Enable action buttons after successful connection
        $processButton.Enabled = $true
        $servicesButton.Enabled = $true
        $diskButton.Enabled = $true
        $eventLogButton.Enabled = $true
        $disconnectButton.Enabled = $true
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to connect to $computerName`n`nError: $_", "Error")
        $statusLabel.Text = "Status: Connection failed"
        $statusLabel.ForeColor = [System.Drawing.Color]::Red
    }
})

# Disconnect button
$disconnectButton = New-Object System.Windows.Forms.Button
$disconnectButton.Location = New-Object System.Drawing.Point(450,20)
$disconnectButton.Size = New-Object System.Drawing.Size(100,20)
$disconnectButton.Text = "Disconnect"
$disconnectButton.Enabled = $false
$disconnectButton.Parent = $managementGroupBox
$disconnectButton.Add_Click({
    $computerName = $computerTextBox.Text
    try {
        Get-PSSession -ComputerName $computerName | Remove-PSSession
        $statusLabel.Text = "Status: Disconnected"
        $statusLabel.ForeColor = [System.Drawing.Color]::Black
        # Disable action buttons after disconnection
        $processButton.Enabled = $false
        $servicesButton.Enabled = $false
        $diskButton.Enabled = $false
        $eventLogButton.Enabled = $false
        $disconnectButton.Enabled = $false
        Write-Log -TextBox $resultsTextBox -Message "Disconnected from $computerName"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error disconnecting: $_", "Error")
    }
})

# Status Label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(10,80)
$statusLabel.Size = New-Object System.Drawing.Size(500,20)
$statusLabel.Text = "Status: Not connected"
$statusLabel.Parent = $managementGroupBox

# Action Buttons Panel
$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonPanel.Location = New-Object System.Drawing.Point(10,110)
$buttonPanel.Size = New-Object System.Drawing.Size(640,40)
$buttonPanel.Parent = $managementGroupBox

# Action Buttons
$processButton = New-Object System.Windows.Forms.Button
$processButton.Size = New-Object System.Drawing.Size(150,30)
$processButton.Text = "View Processes"
$processButton.Enabled = $false
$processButton.Parent = $buttonPanel
$processButton.Add_Click({
    $computerName = $computerTextBox.Text
    try {
        $processes = Invoke-Command -ComputerName $computerName -ScriptBlock { 
            Get-Process | Select-Object Name, ID, CPU, WorkingSet, StartTime, 
            @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB,2)}} 
        }
        $processes | Sort-Object CPU -Descending | Out-GridView -Title "Processes on $computerName"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to retrieve processes`n`nError: $_", "Error")
    }
})

$servicesButton = New-Object System.Windows.Forms.Button
$servicesButton.Size = New-Object System.Drawing.Size(150,30)
$servicesButton.Text = "View Services"
$servicesButton.Enabled = $false
$servicesButton.Parent = $buttonPanel
$servicesButton.Add_Click({
    $computerName = $computerTextBox.Text
    try {
        $services = Invoke-Command -ComputerName $computerName -ScriptBlock { 
            Get-Service | Select-Object Name, DisplayName, Status, StartType 
        }
        $services | Sort-Object Status,Name | Out-GridView -Title "Services on $computerName"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to retrieve services`n`nError: $_", "Error")
    }
})

$diskButton = New-Object System.Windows.Forms.Button
$diskButton.Size = New-Object System.Drawing.Size(150,30)
$diskButton.Text = "Disk Space"
$diskButton.Enabled = $false
$diskButton.Parent = $buttonPanel
$diskButton.Add_Click({
    $computerName = $computerTextBox.Text
    try {
        $disks = Invoke-Command -ComputerName $computerName -ScriptBlock { 
            Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, 
                @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}},
                @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB,2)}},
                @{Name="UsedSpace(GB)";Expression={[math]::Round(($_.Size - $_.FreeSpace)/1GB,2)}},
                @{Name="FreePercent";Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
        }
        $disks | Out-GridView -Title "Disk Space on $computerName"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to retrieve disk information`n`nError: $_", "Error")
    }
})

$eventLogButton = New-Object System.Windows.Forms.Button
$eventLogButton.Size = New-Object System.Drawing.Size(150,30)
$eventLogButton.Text = "System Events"
$eventLogButton.Enabled = $false
$eventLogButton.Parent = $buttonPanel
$eventLogButton.Add_Click({
    $computerName = $computerTextBox.Text
    try {
        $events = Invoke-Command -ComputerName $computerName -ScriptBlock { 
            Get-EventLog -LogName System -Newest 100 | Select-Object TimeGenerated, EntryType, Source, EventID, Message 
        }
        $events | Out-GridView -Title "Recent System Events on $computerName"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to retrieve event logs`n`nError: $_", "Error")
    }
})

# Results area
$resultsTextBox = New-Object System.Windows.Forms.TextBox
$resultsTextBox.Location = New-Object System.Drawing.Point(10,160)
$resultsTextBox.Size = New-Object System.Drawing.Size(640,420)
$resultsTextBox.Multiline = $true
$resultsTextBox.ScrollBars = "Vertical"
$resultsTextBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$resultsTextBox.Parent = $managementGroupBox

# Event handler for computer list selection
$computerList.Add_Click({
    if ($computerList.SelectedItems.Count -gt 0) {
        $computerTextBox.Text = $computerList.SelectedItems[0].Text
    }
})

# Show the form
$form.ShowDialog()
