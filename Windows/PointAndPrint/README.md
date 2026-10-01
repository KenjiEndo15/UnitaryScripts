# Point and Print configuration check

A read-only PowerShell script that checks whether a Windows machine is exposed to the PrintNightmare family of Point and Print privilege-escalation issues (CVE-2021-34527, CVE-2021-34481 and the approved-server spoofing bypass).

It reads the relevant policy values, prints them with the key path they came from, and gives a single verdict. It does not change anything and does not need administrator rights.

## Why
 
Since the August 2021 updates (KB5005652), Windows restricts printer-driver installation to administrators by default. Plenty of environments turned that restriction off to let users install printers themselves, and in doing so reopened a local privilege-escalation path. The settings involved are spread across a few policies with confusing names, so this script just tells you where a given machine stands.

## Usage
 
Run it in the session of a standard user, so the result reflects what that user can actually do:

```ps1
powershell -ExecutionPolicy Bypass -File .\PointAndPrintCheck.ps1
```

## What the verdict means
 
- **SECURE**: driver installation is restricted to administrators. Nothing to do.
- **VULNERABLE, case 1 (PrintNightmare)**: users can install drivers and the security prompts are off. A local user can load an arbitrary DLL as SYSTEM.
- **VULNERABLE, case 2 (Bring Your Own Vulnerable Driver)**: users can install package drivers from any server. A user points at their own print server and pulls in a signed-but-vulnerable driver.
- **RESIDUAL RISK, case 3**: installs are limited to an approved server list, which stops case 2 but is still beatable by spoofing an approved server's name (DNS, LLMNR, etc.). Lower priority, but not nothing.

The fix in every vulnerable case is the same: set "Limits print driver installation to
Administrators" back to Enabled and deploy printer drivers through your usual channel (image,
GPO, SCCM/Intune) instead of letting users pull them.

## Keys it reads
 
All under `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers`:
 
- `PointAndPrint\RestrictDriverInstallationToAdministrators`
- `PointAndPrint\Restricted`
- `PointAndPrint\NoWarningNoElevationOnInstall`
- `PointAndPrint\UpdatePromptSettings`
- `PackagePointAndPrint\PackagePointAndPrintOnly`
- `PackagePointAndPrint\PackagePointAndPrintServerList`
- `PackagePointAndPrint\ListofServers`

## Notes
 
- Windows PowerShell 5.1 (the stock version on Windows 10/11) is enough; nothing needs PS 7.
- Identifying which GPO set a value is out of scope.

## References
- https://itm4n.github.io/printnightmare-exploitation/#fixing-our-point-and-print-configuration
- https://itm4n.github.io/printnightmare-not-over/

# Output Example

```
=== Point and Print check - DESKTOP-X (x) ===                                                                                                                                                                                                                                                                     [OK] Print Spooler service                                   Running / Automatic                                                                                                                                                                                                                                          -------------------------------------------------------------                                                                                                HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint                                                                                                                                                                                                                                                        [OK] RestrictDriverInstallationToAdministrators   1          (= admins only, secure)                                                                         [OK] Restricted                                   not set    (secure)                                                                                        [OK] NoWarningNoElevationOnInstall                not set    (secure)                                                                                        [OK] UpdatePromptSettings                         not set    (secure)                                                                                                                                                                                                                                                     -------------------------------------------------------------                                                                                                HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint                                                                                                                                                                                                                                                 [-]  PackagePointAndPrintOnly                     1                                                                                                          [-]  PackagePointAndPrintServerList               1                                                                                                          [-]  ListofServers (subkey)                       1 server(s)                                                                                                      - prt01.lab.local                                                                                                                                                                                                                                                                                                   -------------------------------------------------------------                                                                                                VERDICT: SECURE - driver installation restricted to administrators.    
```
