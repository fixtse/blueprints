# Log Creation
Start-Transcript -Path "C:\WSLPorts\WSLPorts.log"

# List of ports to Open
$ports = @(11434, 3000);

# Get WSL IP
$wslAddress = bash.exe -c "ip a | grep eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'"

if ($wslAddress -match '^(\d{1,3}\.){3}\d{1,3}$') {
  Write-Host "WSL IP address: $wslAddress" -ForegroundColor Green
  Write-Host "Ports: $ports" -ForegroundColor Green
}
else {
  Write-Host "Error: Could not find WSL IP address." -ForegroundColor Red
  exit
}

$listenAddress = '0.0.0.0';

# Add proxy rules
foreach ($port in $ports) {
  Invoke-Expression "netsh interface portproxy delete v4tov4 listenport=$port listenaddress=$listenAddress";
  Invoke-Expression "netsh interface portproxy add v4tov4 listenport=$port listenaddress=$listenAddress connectport=$port connectaddress=$wslAddress";
}

# Open ports on firewall
$fireWallDisplayName = "WSLPorts";
$portsStr = $ports -join ",";

Invoke-Expression "Remove-NetFireWallRule -DisplayName $fireWallDisplayName";
Invoke-Expression "New-NetFireWallRule -DisplayName $fireWallDisplayName -Direction Outbound -LocalPort $portsStr -Action Allow -Protocol TCP";
Invoke-Expression "New-NetFireWallRule -DisplayName $fireWallDisplayName -Direction Inbound -LocalPort $portsStr -Action Allow -Protocol TCP";

# Avoid WSL being shutdown
wsl --exec dbus-launch true