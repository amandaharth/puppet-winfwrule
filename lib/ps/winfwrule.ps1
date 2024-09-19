param(
    [Parameter(Mandatory)]
    [String] $PuppetAction,
    [String] $Name,
    [String] $Action,
    [String] $Description,
    [String] $Direction,
    [String] $DisplayName,
    [String[]] $FirewallProfile,
    [String[]] $IcmpType,
    [String[]] $LocalAddress,
    [String[]] $LocalPort,
    [String] $Program,
    [String] $Protocol,
    [String] $Service,
    [String[]] $RemoteAddress,
    [String[]] $RemotePort  
)

function get {
    
    if ([string]::IsNullOrEmpty($Name)) {
        # We only care to know about rules that are Enabled on the system, so limit the Get call to rules where Enabled is True
        $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
    } else {
        $rules = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue | Where-Object Enabled -eq True 
    }

    $addr_filter = Get-NetFirewallAddressFilter
    $app_filter = Get-NetFirewallApplicationFilter
    $port_filter = Get-NetFirewallPortFilter
    $service_filter = Get-NetFirewallServiceFilter
    
    $rules_collection = @()
    
    foreach ($rule in $rules) {

        $rules_collection += [PSCustomObject]@{
                                ensure = 'present'
                                name = $rule.InstanceID.ToUpper()
                                action = $rule.Action.ToString().ToLower()
                                description = $rule.Description
                                direction = $rule.Direction.ToString().ToLower()
                                display_name = $rule.DisplayName
                                icmp_type = @($port_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object @{n='IcmpType'; e={$_.IcmpType.ToLower()}} | Select-Object -ExpandProperty IcmpType | Sort-Object)
                                local_address = @($addr_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object @{n='LocalAddress'; e={$_.LocalAddress.ToLower()}} | Select-Object -ExpandProperty LocalAddress | Sort-Object | ForEach-Object { if($_ -match "\/\d+\.\d+\.\d+\.\d+$") { $_ -replace $_.substring($_.IndexOf("/")+1 ),($_.substring($_.IndexOf("/")+1 ) | Convert-SubnetMask) } else { $_ } }) 
                                local_port = @($port_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object @{n='LocalPort'; e={$_.LocalPort.ToLower()}} | Select-Object -ExpandProperty LocalPort | Sort-Object)
                                firewall_profile = @($rule.Profile.ToString().ToLower().Split(',').Trim() | Sort-Object)
                                remote_address = @($addr_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object @{n='RemoteAddress'; e={$_.RemoteAddress.ToLower()}} | Select-Object -ExpandProperty RemoteAddress | Sort-Object | ForEach-Object { if($_ -match "\/\d+\.\d+\.\d+\.\d+$") { $_ -replace $_.substring($_.IndexOf("/")+1 ),($_.substring($_.IndexOf("/")+1 ) | Convert-SubnetMask) } else { $_ } }) 
                                remote_port = @($port_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object @{n='RemotePort'; e={$_.RemotePort.ToLower()}} | Select-Object -ExpandProperty RemotePort | Sort-Object)
                                program = ($app_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object -ExpandProperty Program).ToLower()
                                protocol = ($port_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object -ExpandProperty Protocol).ToString().ToLower()
                                service = ($service_filter | Where-Object InstanceID -eq $rule.InstanceID | Select-Object -ExpandProperty Service).ToLower()
                            } 
    }

    ConvertTo-Json @($rules_collection)

}

function create {

    $Params = @{
        Name = $Name;
        Direction = $Direction;
        Action = $Action;
    }

    if ($Description) {
        $Params.Add("Description", $Description)
    } else {
        $Params.Add("Description", $Name)
    }

    if ($DisplayName) {
        $Params.Add("DisplayName", $DisplayName)
    } else {
        $Params.Add("DisplayName", $Name)
    }

    if ($FirewallProfile) {
        $Params.Add("Profile", $FirewallProfile)
    }

    if ($IcmpType) {
        $Params.Add("IcmpType", $IcmpType)
    }

    if ($LocalAddress) {
        $Params.Add("LocalAddress", $LocalAddress)
    }

    if ($LocalPort) {
        $Params.Add("LocalPort", $LocalPort)
    }

    if ($Program) {
        $Params.Add("Program", $Program)
    }

    if ($Protocol) {
        $Params.Add("Protocol", $Protocol)
    }

    if ($RemoteAddress) {
        $Params.Add("RemoteAddress", $RemoteAddress)
    }

    if ($RemotePort) {
        $Params.Add("RemotePort", $RemotePort)
    }

    if ($Service) {
        $Params.Add("Service", $Service)
    }

    Write-Host "Creating $Name ($DisplayName) with parameters: $($Params.GetEnumerator() | Sort-Object Value | Format-Table | Out-String)"

    try {
        New-NetFirewallRule -Enabled True @Params -ErrorAction Stop
    } catch [Microsoft.Management.Infrastructure.CimException] {
        "Caught error when creating rule. Most likely cause: a rule with this name already exists in Windows Firewall but is in a disabled state. Calling the update function instead for $Name ($DisplayName) with parameters: $($Params.GetEnumerator() | Sort-Object Value | Format-Table | Out-String)"
        update
    } catch {
        throw "Failed to create $Name ($DisplayName) with parameters: $($Params.GetEnumerator() | Sort-Object Value | Format-Table | Out-String)"
        exit 1
    }

}

function update {

    $Params = @{
        Name = $Name;
        Direction = $Direction;
        Action = $Action;
    }

    if ($DisplayName) {
        $Params.Add("NewDisplayName", $DisplayName)
    } 

    if ($FirewallProfile) {
        $Params.Add("Profile", $FirewallProfile)
    }

    if ($IcmpType) {
        $Params.Add("IcmpType", $IcmpType)
    }

    if ($LocalAddress) {
        $Params.Add("LocalAddress", $LocalAddress)
    }

    if ($LocalPort) {
        $Params.Add("LocalPort", $LocalPort)
    }

    if ($Program) {
        $Params.Add("Program", $Program)
    }

    if ($Protocol) {
        $Params.Add("Protocol", $Protocol)
    }

    if ($RemoteAddress) {
        $Params.Add("RemoteAddress", $RemoteAddress)
    }

    if ($RemotePort) {
        $Params.Add("RemotePort", $RemotePort)
    }

    if ($Service) {
        $Params.Add("Service", $Service)
    }

    Write-Host "Updating/enabling $Name ($DisplayName) with parameters: $($Params.GetEnumerator() | Sort-Object Value | Format-Table | Out-String)"

    try {
        Set-NetFirewallRule -Enabled True @Params -ErrorAction Stop
    } catch {
        throw "Failed to update $Name ($DisplayName) with parameters: $($Params.GetEnumerator() | Sort-Object Value | Format-Table | Out-String)"
        exit 1
    }

    try {
        if ($Description) {
            $r = Get-NetFirewallRule -Name $Name -ErrorAction Stop
            $r.Description = $Description 
            $r | Set-NetFirewallRule
        }
    } catch {
        throw "Failed to set description for $Name ($DisplayName) to: ""$Description"""
        exit 1
    }

}

function delete {
    # When a Purge/Delete is done by Puppet, the firewall rule is set to DISABLED in Windows Firewall. It is NOT deleted from the system.
    # This is by design.
    
    Write-Host "Disabling $Name"

    try {
        Disable-NetFirewallRule -Name "$Name" -ErrorAction Stop
    } catch {
        throw "Failed to disable $Name"
        exit 1
    }

}

function Convert-SubnetMask {
    <#
    .DESCRIPTION
        Convert a subnet mask to CIDR prefix length
    .EXAMPLE
        This example calculates the prefix length of 255.255.254.0 netmask:
        PS C:\Windows\system32> Convert-SubnetMask -SubnetMask 255.255.254.0
		23       
    #>
    param (
        # Subnet mask to convert, provided in 255.255.255.0 form
        [Parameter(ValueFromPipeline)]
        [String]$SubnetMask
    )

    $binaryForm = ""

    # Convert each mask octet to binary and combine into 1 string
    $SubnetMask.split(".") | ForEach-Object { $binaryForm += [Convert]::ToString($_, 2).PadLeft(8, '0') }

    if ($binaryForm -match "0") {
	# Return the index of the first 0 found in the binary string, if there is a 0 present
        $prefixLength = $binaryForm.IndexOf('0')
    }
    else {
	# Count the number of bits/"1"s to get the prefix length
        $prefixLength = ([regex]::Matches($binaryForm, "1" )).Count
    }
    return $prefixLength
    
}

function check_rule_safety {
    # NEED TO SAFEGUARD AGAINST CREATING ANY:ANY RULES
}

switch ($PuppetAction) {

    "get" {
        get
    }
    "create" {
        create
    }
    "update" {
        update
    }
    "delete" {
        delete
    }
    default {
        throw "Unhandled action specified, no action taken: $($PuppetAction)"
        exit 1
    }

}
