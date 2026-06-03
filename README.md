# USB Forensic Viewer

A Windows PowerShell-based cyber security tool that provides a forensic view of all USB devices ever connected to a system — including plug/unplug timestamps, device details, serial numbers, driver information, and full event history.

## Features

- **Historical device inventory** — reads registry (`USBSTOR` and `USB` hives) for every device ever connected
- **Live connection status** — detects currently connected devices via WMI
- **Plug/unplug timestamps** — queries Windows Event Log (`System`, `Kernel-PnP`, `DriverFrameworks-UserMode`) for precise connection history
- **Setupapi.dev.log fallback** — fills in dates for devices with no event log entries
- **Rich device metadata** — Vendor ID, Product ID, serial number, manufacturer, firmware revision, driver, service, USB class/subclass/protocol
- **Dark forensics-themed GUI** — sortable, filterable data grid with a detail panel and event history log
- **Export** — save results to CSV or styled HTML report
- **Filter / search** — real-time text filter across all device fields

## Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 10 / 11 (or Windows Server 2016+) |
| PowerShell | 5.1 or later (included in Windows) |
| Privileges | Standard user for basic data; **Run as Administrator** for full registry and event log access |

## Quick Start

Double-click `Launch-USBForensics.bat`.  
For full data, right-click → **Run as administrator**.

## Usage

| Control | Action |
|---|---|
| `[ REFRESH ]` | Re-scan registry, WMI, and event logs |
| `[ EXPORT CSV ]` | Save all visible rows to a `.csv` file |
| `[ EXPORT HTML ]` | Save a styled HTML forensics report |
| `FILTER:` box | Type any text to filter the device list in real time |
| Click a row | View full forensic detail and plug/unplug event log in the right panel |

## Data Sources

| Source | Data Collected |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | Mass storage devices (drives, flash drives) |
| `HKLM\SYSTEM\CurrentControlSet\Enum\USB` | All other USB devices (HID, audio, hubs, etc.) |
| `Win32_USBControllerDevice` (WMI) | Live connection status |
| Windows Event Log — System, Kernel-PnP, DriverFrameworks | Plug/unplug timestamps (Event IDs 20001, 20003, 20009, 400, 410, 2003, 2100) |
| `%WINDIR%\inf\setupapi.dev.log` | Device install timestamps (fallback) |

## Output Fields

`Device Name` · `Type` · `Vendor ID` · `Product ID` · `Serial Number` · `Manufacturer` · `Last Plug` · `Last Unplug` · `Connected` · `Disabled` · `Drive Letter` · `USB Version` · `Class / SubClass / Protocol` · `Service` · `Driver`

## Notes

- Serial numbers ending in `&0` or `&1` are Windows-generated (the device has no embedded serial).  
- Devices with no event log history will show registry `LastWriteTime` as the last plug date.  
- Some event IDs require the **DriverFrameworks-UserMode/Operational** log to be enabled; the tool queries it silently if unavailable.

## License

MIT — see [LICENSE](LICENSE).
