# py-deauth
Spams Deauth frames over WIFI

Usage: `deauth.py <interface> [-v] [-b | -c client] [-n network] [-f freq | -r range]`

### Options

 Option | Flag | Description
 --- | --- | ---
 `--broadcast` | `-b` | Broadcast to all clients using `ff:ff:ff:ff:ff:ff`
 `--client` | `-c` | Deauth a specific client
 `--freq=` | `-f=` | Frequency to scan
 `--network=` | `-n=` | Deauth access points broadcasting a specific SSID
 `--range=` | `-r` | Frequency range to scan ("2.4" or "5")
 `--verbose` | `-v` | Print Details
 
 Do not hold the developer(s) accountable for any action you use with this tool.
