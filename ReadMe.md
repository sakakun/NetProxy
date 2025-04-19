# NetLimiter Proxy Checker

A tool for monitoring and managing network connections, focusing on identifying and handling VPN or proxy connections.

## Requirements
- NetLimiter (Latest Version)
- .NET Framework 4.5 or higher

## Setup

### NetLimiter Configuration
1. Create a filter in NetLimiter:
   - **Filter Name**: `VPN Block` // Can be any name, as long as you place it in the Settings.ini the same.
   - **Filter Type**: `Filter`
   - **Per-Type**: `Per-Connection`
   - **Filter Functions**:
     - Add a new function: `Remote Address in Range`.
     - Add at least one IP address to initialize the filter.
   - Save the filter and select it in the Filter List screen.
   - Under **Filter View -> Rules**:
     - Set **Blocker In/Out** to `Deny`.
     - Set **Priority** to `Critical`.

### `settings.ini` Configuration
1. Update the following fields in `settings.ini`:
   - **Host Information**: Use `localhost` or `127.0.0.1` if running on the same machine.
     - If Running on Host, run as admin.
   - **Proxy Checker**: Set the proxy service and API key.
   - **Whitelist**: Add any IPs to ignore.

Refer to the example `settings.ini` file for detailed configuration options.