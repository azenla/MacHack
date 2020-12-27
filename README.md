# MacHack

A list of built-in tools in macOS that you probably didn't know about.

## Table of Contents

- [MacHack](#machack)
  - [Table of Contents](#table-of-contents)
  - [Commands](#commands)
    - [java_home](#java_home)
    - [dot_clean](#dot_clean)
    - [SafeEjectGPU](#safeejectgpu)
    - [sharing](#sharing)
    - [remotectl](#remotectl)
    - [brctl](#brctl)
    - [sysadminctl](#sysadminctl)
    - [ckksctl](#ckksctl)
    - [otctl](#otctl)
    - [spctl](#spctl)
    - [networksetup](#networksetup)
    - [systemsetup](#systemsetup)
    - [airport](#airport)
    - [AssetCacheLocatorUtil](#assetcachelocatorutil)
    - [AssetCacheManagerUtil](#assetcachemanagerutil)
    - [seedutil](#seedutil)
    - [kmutil](#kmutil)
    - [profiles](#profiles)
    - [bputil](#bputil)

## Commands

### java_home

This tool queries the available Java Virtual Machines from `/Library/Java/JavaVirtualMachines`.

```text
$ /usr/libexec/java_home --help
Usage: java_home [options...]
    Returns the path to a Java home directory from the current user's settings.

Options:
    [-v/--version   <version>]       Filter Java versions in the "JVMVersion" form 1.X(+ or *).
    [-a/--arch      <architecture>]  Filter JVMs matching architecture (i386, x86_64, etc).
    [-d/--datamodel <datamodel>]     Filter JVMs capable of -d32 or -d64
    [-t/--task      <task>]          Use the JVM list for a specific task (Applets, WebStart, BundledApp, JNI, or CommandLine)
    [-F/--failfast]                  Fail when filters return no JVMs, do not continue with default.
    [   --exec      <command> ...]   Execute the $JAVA_HOME/bin/<command> with the remaining arguments.
    [-X/--xml]                       Print full JVM list and additional data as XML plist.
    [-V/--verbose]                   Print full JVM list with architectures.
    [-h/--help]                      This usage information.
```

An example usage of this tool:

```text
$ /usr/libexec/java_home -v 11 -a x86_64
/Library/Java/JavaVirtualMachines/adoptopenjdk-11.jdk/Contents/Home
```

### dot_clean

This is an extremely useful built-in utility to delete all useless dot files that macOS creates, such as ._MyFile.

Just point it at a folder, and it wipes it free of the cruft!

```text
$ /usr/sbin/dot_clean
usage: dot_clean  [-fmnpsv] [--keep=[mostrecent|dotbar|native]] [directory ...]
```

An example usage of the tool:

```text
$ /usr/sbin/dot_clean /Volumes/Shared/MyFiles
```

### SafeEjectGPU

This is a utility for managing GPUs, especially eGPUs. This is what is behind
the safe eject functionality of the eGPU in the System UI.

It is useful for:

- Listing GPUs on the system.
- Determining what applications are using a particular GPU.
- Ejecting an eGPU safely.
- Launching an application on a specific GPU.
- Switching an application from one GPU to another.

```text
$ /usr/bin/SafeEjectGPU
usage: SafeEjectGPU [Commands...]
    Commands:
        gpuid <gpuid> # specify gpuid of following commands
        gpuids <gpuid1>,<gpuid2>,... # specify list of gpuids for RelaunchPIDOnGPU command
        gpus          # show all GPUs and their applicable properties
        apps          # show all Apps on specified gpuid
        status        # show status of all specified gpuid
        Eject         # Eject (full eject sequence) on specified gpuid
        Initiate      # Initiate eject sequence on specified gpuid
        Relaunch      # Relaunch lingering AppKit apps on specified gpuid
        Finalize      # Finalize eject sequence on specified gpuid
        Cancel        # Cancel eject sequence on specified gpuid
        RelaunchPID <pid>       # RelaunchPID can be used in app testing to send Relaunch stimulus in isolation
        RelaunchPIDOnGPU <pid>  # Send Relaunch stimulus to an app with set of limited GPUs to select from, use gpuids
        LaunchOnGPU <path>      # Launch an app from given bundle path with set of limited GPUs, use gpuids
        zombies       # show all zombies (apps holding reference to unplugged eGPU)
        zcount        # show count of (unhidden) zombies
        Zkill         # kill zombies
        Zrelaunch     # relaunch zombies
        +fallbackGPUEjectPolicy # allow builtin fallbacks to take effect (default)
        -fallbackGPUEjectPolicy # deny builtin fallbacks

    Notes:
       Unspecified gpuid (==0) indicates all "removable" GPUs
       Capitalized commands may have system-wide effects
       Non-capitalized commands are informative only
       See description of Info.plist "SafeEjectGPUPolicy" key.  Use values:
           "ignore", "wait", "relaunch", or "kill" for per-app policy
       +/-fallbackGPUEjectPolicy can appear multiple times on the commandline and applies to following commands
```

Example of the `gpus` command:

```text
$ /usr/bin/SafeEjectGPU gpus
gpus
2019-10-13 10:04:58.676 SafeEjectGPU[53035:3374543] Device PreExisted [000000010000778d] AMD Radeon RX 570
2019-10-13 10:04:58.676 SafeEjectGPU[53035:3374543] Device PreExisted [000000010000086b] AMD Radeon Pro 560X
2019-10-13 10:04:58.676 SafeEjectGPU[53035:3374543] Device PreExisted [000000010000081a] Intel(R) UHD Graphics 630
gpuid 0x56ce - Intel® UHD Graphics 630
               registryID=0x000000010000081a integrated
               location - BuiltIn
               locationNumber - 0
               maxTransferRate - 0
gpuid 0x9f05 - AMD Radeon Pro 560X
               registryID=0x000000010000086b discrete
               location - BuiltIn
               locationNumber - 1
               maxTransferRate - 0
gpuid 0x5d0e - AMD Radeon RX 570
               registryID=0x000000010000778d removable
               Razer Core X - enclosureRegistryID=0x000000010000776d
               location - External
               locationNumber - 4
               maxTransferRate - 5000000000
```

### sharing

This command gives information about File Sharing. It should look similar to the File Sharing section in the Sharing preference pane.

```bash
$ /usr/sbin/sharing
Usage:
sharing -a <path> [options] : create a sharepoint for directory specified by path <path>
sharing -e <name> [options] : edit sharepoint named <name>
sharing -r <name>           : remove sharepoint with name <name>
sharing -l                  : list existing  sharepoints

options:
        -A <name> :use share point name <name> for afp.
        -F <name> :use share point name <name> for ftp.
        -S <name> :use share point name <name> for smb.
        -s [<flags>] :enable sharing, restricted by flags if specified;
           flags = 000,001,010 ...111; 1 = share, 0 = do not share;
           with digits indicating afp, ftp (no longer supported) and smb in that order;
           default is 101 if -s is specified with no flags.
        -g [<flags>] :enable guest access, restricted by flags if specified;
           flags = 000,001,010 ...111; 1 = enabled, 0 = disabled;
           with digits indicating afp, ftp (no longer supported) and smb in that order;
           default 101 if -g is specified with no flags.
        -i [<flags>] :enable inherit privileges from parent(afp only), restricted by flags if specified;
           flags = 00,10; 10 = enabled, 00 = disabled;
           default is 10 if -i is specified with no flags.
        -n <name> :set record name to use (by default this is the directory name of the shared directory)
```

### remotectl

The Apple T2 security chip (a built-in ARM chip in newer Mac models) communicates with your system with a modified HTTP/2 protocol. There is also a command-line interface for various functions of the chip.

```text
$ /usr/libexec/remotectl
usage: remotectl list
usage: remotectl show (name|uuid)
usage: remotectl get-property (name|uuid) [service] property
usage: remotectl dumpstate
usage: remotectl browse
usage: remotectl echo [-v service_version] [-d (name|uuid)]
usage: remotectl echo-file (name|uuid) path
usage: remotectl eos-echo
usage: remotectl netcat (name|uuid) service
usage: remotectl relay (name|uuid) service
usage: remotectl loopback (attach|connect|detach|suspend|resume)
usage: remotectl bonjour ((enable|enable-loopback interface_name)|(disable))
usage: remotectl convert-bridge-version plist-in-path bin-out-path
usage: remotectl heartbeat (name|uuid)
usage: remotectl trampoline [-2 fd] service_name command args ... [ -- [-2 fd] service_name command args ... ]
```

Example of the `list` command:

```text
$ /usr/libexec/remotectl list
MY_UUID_HERE localbridge      iBridge2,3   J680AP   4.0 (17P572/17.16.10572.0.0,0) -
```

Example of the `show` command:

```text
$ /usr/libexec/remotectl show MY_UUID_HERE
Found localbridge (bridge)
        State: connected (connectable)
        UUID: MY_UUID_HERE
        Product Type: iBridge2,3
        OS Build: 4.0 (17P572)
        Messaging Protocol Version: 1
        Heartbeat:
                Last successful heartbeat sent 18.730s ago, received 18.727s ago (took 0.002s)
                6147 heartbeats sent, 0 received
        Properties: {
                AppleInternal => false
                ChipID => 32786
                EffectiveProductionStatusSEP => true
                HWModel => J680AP
                HasSEP => true
                LocationID => 2148532224
                RegionInfo => LL/A
                EffectiveSecurityModeAp => true
                FDRSealingStatus => true
                SigningFuse => true
                BuildVersion => 17P572
                OSVersion => 4.0
                BridgeVersion => 17.16.10572.0.0,0
                SensitivePropertiesVisible => true
                ProductType => iBridge2,3
                BoardRevision => 1
                Image4CryptoHashMethod => sha2-384
                SerialNumber => MY_SERIAL_NUMBER_HERE
                BootSessionUUID => MY_BOOT_UUID_HERE
                BoardId => 11
                DeviceColor => black
                EffectiveProductionStatusAp => true
                EffectiveSecurityModeSEP => true
                UniqueChipID => MY_UNIQUE_CHIP_ID
                UniqueDeviceID => MY_UNIQUE_DEVICE_ID
                RemoteXPCVersionFlags => 72057594037927942
                CertificateSecurityMode => true
                CertificateProductionStatus => true
                DeviceEnclosureColor => black
                ModelNumber => Z0V16LL/A
                RegionCode => LL
                SecurityDomain => 1
                InterfaceIndex => 4
                HardwarePlatform => t8012
                Image4Supported => true
        }
        Services:
                com.apple.powerchime.remote
                com.apple.mobile.storage_mounter_proxy.bridge
                com.apple.lskdd
                com.apple.eos.BiometricKit
                com.apple.aveservice
                com.apple.icloud.findmydeviced.bridge
                com.apple.private.avvc.xpc.remote
                com.apple.nfcd.relay.control
                com.apple.corespeech.xpc.remote.control
                com.apple.mobileactivationd.bridge
                com.apple.sysdiagnose.stackshot.remote
                com.apple.multiverse.remote.bridgetime
                com.apple.eos.LASecureIO
                com.apple.xpc.remote.multiboot
                com.apple.nfcd.relay.uart
                com.apple.xpc.remote.mobile_obliteration
                com.apple.corespeech.xpc.remote.record
                com.apple.sysdiagnose.remote
                com.apple.mobile.storage_mounter_proxy.bridge.macOS
                com.apple.bridgeOSUpdated
                com.apple.osanalytics.logTransfer
                com.apple.internal.xpc.remote.kext_audit
                com.apple.recoverylogd.bridge
                com.apple.corecaptured.remoteservice
                com.apple.logd.remote-daemon
                com.apple.videoprocessingd.encode.remote
```

### brctl

This is a utility related to "CloudDocs", also know as iCloud Drive.

```text
$ brctl
Usage: brctl <command> [command-options and arguments]

    -h,--help            show this help

COMMANDS

diagnose [options] [--doc|-d <document-path>] [<diagnosis-output-path>]
    diagnose and collect logs

    -M,--collect-mobile-documents[=<container>]  (default: all containers)
    -s,--sysdiagnose     Do not collect what's already part of sysdiagnose
    -t,--uitest          Collect logs for UI tests
    -n,--name=<name>     Change the device name
    -f,--full            Do a full diagnose, including server checks
    -d,--doc=<document-path>
                         Collect additional information about the document at that path.
                         Helps when investigating an issue impacting a specific document.
    -e,--no-reveal       Do not reveal diagnose in the Finder when done
    [<diagnosis-output-path>]
                         Specifies the output path of the diagnosis; -n becomes useless.

log [options] [<command>]

    -a,--all                         Show all system logs
    -p,--predicate                   Additional predicate (see `log help predicates`)
    -x,--process <name>              Filter events from the specified process
    -d,--path=<logs-dir>             Use <logs-dir> instead of default
    -S,--start="YYYY-MM-DD HH:MM:SS" Start log dump from a specified date
    -E,--end="YYYY-MM-DD HH:MM:SS"   Stop log dump after a specified date
    -b                               Only show CloudDocs logs
    -f                               Only show FileProvider related logs
    -g                               Only show Genstore related logs
    -z,--local-timezone              Display timestamps within local timezone

dump [options] [<container>]
    dump the CloudDocs database

    -o,--output=<file-path>
                         redirect output to <file-path>
    -d,--database-path=<db-path>
                         Use the database at <db-path>
    -i,--itemless
                         Don't dump items from the db
    -u,--upgrade
                         Upgrade the db if necessary before dumping

    [<container>]        the container to be dumped

status [<containers>]
    Prints items which haven't been completely synced up / applied to disk

    [<container>]        the container to be dumped

quota
    Displays the available quota in the account

monitor [options] [<container> ...]
    monitor activity
    -g                   dump global activity of the iCloud Drive
    -i                   dump changes incrementally
    -S,--scope=<scope>
                         restrict the NSMetadataQuery scope to docs, data, external or a combination

    [<container> ...]    list of containers to monitor, ignored when -g is used
```

A pretty cool command here is a utility to get the quota left on your iCloud Drive:

```text
$ brctl quota
2098962726220 bytes of quota remaining
```

### sysadminctl

Basically an all around useful tool for managing users, as well as manage full-disk encryption (FileVault).

```text
$ /usr/sbin/sysadminctl
Usage: sysadminctl
        -deleteUser <user name> [-secure || -keepHome] (interactive || -adminUser <administrator user name> -adminPassword <administrator password>)
        -newPassword <new password> -oldPassword <old password> [-passwordHint <password hint>]
        -resetPasswordFor <local user name> -newPassword <new password> [-passwordHint <password hint>] (interactive] || -adminUser <administrator user name> -adminPassword <administrator password>)
        -addUser <user name> [-fullName <full name>] [-UID <user ID>] [-shell <path to shell>] [-password <user password>] [-hint <user hint>] [-home <full path to home>] [-admin] [-picture <full path to user image>] (interactive] || -adminUser <administrator user name> -adminPassword <administrator password>)
        -secureTokenStatus <user name>
        -secureTokenOn <user name> -password <password> (interactive || -adminUser <administrator user name> -adminPassword <administrator password>)
        -secureTokenOff <user name> -password <password> (interactive || -adminUser <administrator user name> -adminPassword <administrator password>)
        -guestAccount <on || off || status>
        -afpGuestAccess <on || off || status>
        -smbGuestAccess <on || off || status>
        -automaticTime <on || off || status>
        -filesystem status
        -screenLock <immediate || off> -password <password>

Pass '-' instead of password in commands above to request prompt.
'-adminPassword' used mostly for scripted operation. Use '-' or 'interactive' to get the authentication string interactively. This preferred for security reasons
```

A pretty useful command in this tool is to check if FileVault is enabled:

```text
$ sudo sysadminctl -filesystem status
2019-10-13 10:16:41.266 sysadminctl[61797:3404423] Boot volume CS FDE: NO
2019-10-13 10:16:41.298 sysadminctl[61797:3404423] Boot volume APFS FDE: YES
```

### ckksctl

CloudKit controls, probably useful for some advanced users.

```text
$ /usr/sbin/ckksctl
usage: ckksctl [-p] [-j] [-v arg] [status] [fetch] [push] [resync] [reset] [reset-cloudkit] [ckmetric]

Control and report on CKKS

positional arguments:

optional arguments:
  -p, --perfcounters             Print CKKS performance counters
  -j, --json                     Output in JSON format
  -v arg, --view arg             Operate on a single view

optional commands:
  status                         Report status on CKKS views
  fetch                          Fetch all new changes in CloudKit and attempt to process them
  push                           Push all pending local changes to CloudKit
  resync                         Resync all data with what's in CloudKit
  reset                          All local data will be wiped, and data refetched from CloudKit
  reset-cloudkit                 All data in CloudKit will be removed and replaced with what's local
  ckmetric                       Push CloudKit metric
```

### otctl

This is the Octagon Trust utility. It's a pretty neat view of the underlying trust network being used by your Apple Devices.

```text
$ /usr/sbin/otctl
usage: otctl [-s arg] [-e arg] [-r arg] [-j] [--altDSID arg] [--entropy arg] [--container arg] [--radar arg] [start] [sign-in] [sign-out] [status] [resetoctagon] [allBottles] [recover] [depart] [er-trigger] [er-status] [er-reset] [er-store] [health] [taptoradar]

Control and report on Octagon Trust

positional arguments:

optional arguments:
  -s arg, --secret arg           escrow secret
  -e arg, --bottleID arg         bottle record id
  -r arg, --skipRateLimiting arg  enter values YES or NO, option defaults to NO, This gives you the opportunity to skip the rate limiting check when performing the cuttlefish health check
  -j, --json                     Output in JSON
  --altDSID arg                   altDSID (for sign-in/out)
  --entropy arg                   escrowed entropy in JSON
  --container arg                 CloudKit container name
  --radar arg                     Radar number

optional commands:
  start                          Start Octagon state machine
  sign-in                        Inform Cuttlefish container of sign in
  sign-out                       Inform Cuttlefish container of sign out
  status                         Report Octagon status
  resetoctagon                   Reset and establish new Octagon trust
  allBottles                     Fetch all viable bottles
  recover                        Recover using this bottle
  depart                         Depart from Octagon Trust
  er-trigger                     Trigger an Escrow Request request
  er-status                      Report status on any pending Escrow Request requests
  er-reset                       Delete all Escrow Request requests
  er-store                       Store any pending Escrow Request prerecords
  health                         Check Octagon Health status
  taptoradar                     Trigger a TapToRadar
```

Run the following command to list your peers:

```text
$ /usr/sbin/otctl status
... Lots of Useful Output ...
```

### spctl

This is the System Policy management utility. You can enable and disable Gatekeeper and other code-signing features this way.

```text
$ /usr/sbin/spctl
System Policy Basic Usage:
       spctl --assess [--type type] [-v] path ... # assessment
       spctl --add [--type type] [--path|--requirement|--anchor|--hash] spec ... # add rule(s)
       spctl [--enable|--disable|--remove] [--type type] [--path|--requirement|--anchor|--hash|--rule] spec # change rule(s)
       spctl --status | --master-enable | --master-disable # system master switch

Developer Mode Usage:
    spctl developer-mode <action>
        enable-terminal
            Add Terminal as a developer tool.
Kernel Extension User Consent Usage:
    spctl kext-consent <action>         ** Modifications only available in Recovery OS **
        status
            Print whether kernel extension user consent is enabled or disabled.
        enable
            Enable requiring user consent for kernel extensions.
        disable
            Disable requiring user consent for kernel extensions.
        add <team-id>
            Insert a new Team Identifier into the list allowed to load kernel extensions without user consent.
        list
            Print the list of Team Identifiers allowed to load without user consent.
        remove <team-id>
            Remove a Team Identifier from the list allowed to load kernel extensions without user consent.
```

A useful command is to view the status of the system policy assesments:

```text
$ /usr/sbin/spctl --status
assessments enabled
```

### networksetup

Network setup is pretty much everything network-related minus some wireless stuff.

```text
$ /usr/sbin/networksetup
networksetup Help Information
-------------------------------
Usage: networksetup -listnetworkserviceorder
    Display services with corresponding port and device in order they are tried for connecting
    to a network. An asterisk (*) denotes that a service is disabled.

Usage: networksetup -listallnetworkservices
    Display list of services. An asterisk (*) denotes that a network service is disabled.

Usage: networksetup -listallhardwareports
    Display list of hardware ports with corresponding device name and ethernet address.

Usage: networksetup -detectnewhardware
    Detect new network hardware and create a default network service on the hardware.

Usage: networksetup -getmacaddress <hardwareport or device name>
    Display ethernet (or Wi-Fi) address for hardwareport or device specified.

Usage: networksetup -getcomputername
    Display the computer name.

Usage: networksetup -setcomputername <name>
    Set the computer's name (if valid) to <name>.

Usage: networksetup -getinfo <networkservice>
    Display IPv4 address, IPv6 address, subnet mask,
    router address, ethernet address for <networkservice>.

Usage: networksetup -setmanual <networkservice> <ip> <subnet> <router>
    Set the <networkservice> TCP/IP configuration to manual with IP address set to ip,
    Subnet Mask set to subnet, and Router address set to router.

Usage: networksetup -setdhcp <networkservice> [clientid]
    Set the <networkservice> TCP/IP configuration to DHCP. You can set the
     DHCP client id to the optional [clientid]. Specify "Empty" for [clientid]
    to clear the DHCP client id.

Usage: networksetup -setbootp <networkservice>
    Set the <networkservice> TCP/IP configuration to BOOTP.

Usage: networksetup -setmanualwithdhcprouter <networkservice> <ip>
    Set the <networkservice> TCP/IP configuration to manual with DHCP router with IP address set
    to ip.

Usage: networksetup -getadditionalroutes <networkservice>
    Get additional IPv4 routes associated with <networkservice>
Usage: networksetup -setadditionalroutes <networkservice> [ <dest> <mask> <gateway> ]*
    Set additional IPv4 routes associated with <networkservice>
    by specifying one or more [ <dest> <mask> <gateway> ] tuples.
    Remove additional routes by specifying no arguments.
    If <gateway> is "", the route is direct to the interface
Usage: networksetup -setv4off <networkservice>
    Turn IPv4 off on <networkservice>.

Usage: networksetup -setv6off <networkservice>
    Turn IPv6 off on <networkservice>.

Usage: networksetup -setv6automatic <networkservice>
    Set the service to get its IPv6 info automatically.

Usage: networksetup -setv6LinkLocal <networkservice>
    Set the service to use its IPv6 only for link local.

Usage: networksetup -setv6manual <networkservice> <address> <prefixlength> <router>
    Set the service to get its IPv6 info manually.
    Specify <address> <prefixLength> and <router>.

Usage: networksetup -getv6additionalroutes <networkservice>
    Get additional IPv6 routes associated with <networkservice>
Usage: networksetup -setv6additionalroutes <networkservice> [ <dest> <prefixlength> <gateway> ]*
    Set additional IPv6 routes associated with <networkservice>
    by specifying one or more [ <dest> <prefixlength> <gateway> ] tuples.
    Remove additional routes by specifying no arguments.
    If <gateway> is "", the route is direct to the interface
Usage: networksetup -getdnsservers <networkservice>
    Display DNS info for <networkservice>.

Usage: networksetup -setdnsservers <networkservice> <dns1> [dns2] [...]
    Set the <networkservice> DNS servers to <dns1> [dns2] [...]. Any number of dns servers can be
    specified. Specify "Empty" for <dns1> to clear all DNS entries.

Usage: networksetup -getsearchdomains <networkservice>
    Display Domain Name info for <networkservice>.

Usage: networksetup -setsearchdomains <networkservice> <domain1> [domain2] [...]
    Set the <networkservice> Domain Name servers to <domain1> [domain2] [...]. Any number of Domain Name
     servers can be specified. Specify "Empty" for <domain1> to clear all Domain Name entries.

Usage: networksetup -create6to4service <newnetworkservicename>
    Create a 6 to 4 service with name <newnetworkservicename>.

Usage: networksetup -set6to4automatic <networkservice>
    Set the service to get its 6 to 4 info automatically.

Usage: networksetup -set6to4manual <networkservice> <relayaddress>
    Set the service to get its 6 to 4 info manually.
    Specify <relayaddress> for the relay address.

Usage: networksetup -getftpproxy <networkservice>
    Display FTP proxy (server, port, enabled value) info for <networkservice>.

Usage: networksetup -setftpproxy <networkservice> <domain> <port number> <authenticated> <username> <password>
    Set FTP proxy for <networkservice> with <domain> and <port number>. Turns proxy on. Optionally, specify <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify <username> and <password> if you turn authenticated proxy support on.

Usage: networksetup -setftpproxystate <networkservice> <on off>
    Set FTP proxy to  either <on> or <off>.

Usage: networksetup -getwebproxy <networkservice>
    Display Web proxy (server, port, enabled value) info for <networkservice>.

Usage: networksetup -setwebproxy <networkservice> <domain> <port number> <authenticated> <username> <password>
    Set Web proxy for <networkservice> with <domain> and <port number>. Turns proxy on. Optionally, specify <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify <username> and <password> if you turn authenticated proxy support on.

Usage: networksetup -setwebproxystate <networkservice> <on off>
    Set Web proxy to  either <on> or <off>.

Usage: networksetup -getsecurewebproxy <networkservice>
    Display Secure Web proxy (server, port, enabled value) info for <networkservice>.

Usage: networksetup -setsecurewebproxy <networkservice> <domain> <port number> <authenticated> <username> <password>
    Set Secure Web proxy for <networkservice> with <domain> and <port number>. Turns proxy on. Optionally, specify <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify <username> and <password> if you turn authenticated proxy support on.

Usage: networksetup -setsecurewebproxystate <networkservice> <on off>
    Set SecureWeb proxy to  either <on> or <off>.

Usage: networksetup -getstreamingproxy <networkservice>
    Display Streaming proxy (server, port, enabled value) info for <networkservice>.

Usage: networksetup -setstreamingproxy <networkservice> <domain> <port number> <authenticated> <username> <password>
    Set Streaming proxy for <networkservice> with <domain> and <port number>. Turns proxy on. Optionally, specify <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify <username> and <password> if you turn authenticated proxy support on.

Usage: networksetup -setstreamingproxystate <networkservice> <on off>
    Set Streaming proxy to  either <on> or <off>.

Usage: networksetup -getgopherproxy <networkservice>
    Display Gopher proxy (server, port, enabled value) info for <networkservice>.

Usage: networksetup -setgopherproxy <networkservice> <domain> <port number> <authenticated> <username> <password>
    Set Gopher proxy for <networkservice> with <domain> and <port number>. Turns proxy on. Optionally, specify <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify <username> and <password> if you turn authenticated proxy support on.

Usage: networksetup -setgopherproxystate <networkservice> <on off>
    Set Gopher proxy to  either <on> or <off>.

Usage: networksetup -getsocksfirewallproxy <networkservice>
    Display SOCKS Firewall proxy (server, port, enabled value) info for <networkservice>.

Usage: networksetup -setsocksfirewallproxy <networkservice> <domain> <port number> <authenticated> <username> <password>
    Set SOCKS Firewall proxy for <networkservice> with <domain> and <port number>. Turns proxy on. Optionally, specify <on> or <off> for <authenticated> to enable and disable authenticated proxy support. Specify <username> and <password> if you turn authenticated proxy support on.

Usage: networksetup -setsocksfirewallproxystate <networkservice> <on off>
    Set SOCKS Firewall proxy to  either <on> or <off>.

Usage: networksetup -getproxybypassdomains <networkservice>
    Display Bypass Domain Names for <networkservice>.

Usage: networksetup -setproxybypassdomains <networkservice> <domain1> [domain2] [...]
    Set the Bypass Domain Name Servers for <networkservice> to <domain1> [domain2] [...]. Any number of
    Domain Name servers can be specified. Specify "Empty" for <domain1> to clear all
    Domain Name entries.

Usage: networksetup -getproxyautodiscovery <networkservice>
    Display whether Proxy Auto Discover is on or off for <network service>.

Usage: networksetup -setproxyautodiscovery <networkservice> <on off>
    Set Proxy Auto Discovery to either <on> or <off>.

Usage: networksetup -getpassiveftp <networkservice>
    Display whether Passive FTP is on or off for <networkservice>.

Usage: networksetup -setpassiveftp <networkservice> <on off>
    Set Passive FTP to either <on> or <off>.

Usage: networksetup -setautoproxyurl <networkservice> <url>
    Set proxy auto-config to url for <networkservice> and enable it.

Usage: networksetup -getautoproxyurl <networkservice>
    Display proxy auto-config (url, enabled) info for <networkservice>.

Usage: networksetup -setautoproxystate <networkservice> <on off>
    Set proxy auto-config to either <on> or <off>.

Usage: networksetup -getairportnetwork <device name>
    Display current Wi-Fi Network for <device name>.

Usage: networksetup -setairportnetwork <device name> <network> [password]
    Set Wi-Fi Network to <network> for <device name>.
    If a password is included, it gets stored in the keychain.

Usage: networksetup -getairportpower <device name>
    Display whether Wi-Fi power is on or off for <device name>.

Usage: networksetup -setairportpower <device name> <on off>
    Set Wi-Fi power for <device name> to either <on> or <off>.

Usage: networksetup -listpreferredwirelessnetworks <device name>
    List the preferred wireless networks for <device name>.

Usage: networksetup -addpreferredwirelessnetworkatindex <device name> <network> <index> <security type> [password]
    Add wireless network named <network> to preferred list for <device name> at <index>.
    For security type, use OPEN for none, WPA for WPA Personal, WPAE for WPA Enterprise,
    WPA2 for WPA2 Personal, WPA2E for WPA2 Enterprise, WEP for plain WEP, and 8021XWEP for 802.1X WEP.
    If a password is included, it gets stored in the keychain.

Usage: networksetup -removepreferredwirelessnetwork <device name> <network>
    Remove <network> from the preferred wireless network list for <device name>.

Usage: networksetup -removeallpreferredwirelessnetworks <device name>
    Remove all networks from the preferred wireless network list for <device name>.

Usage: networksetup -getnetworkserviceenabled <networkservice>
    Display whether a service is on or off (enabled or disabled).

Usage: networksetup -setnetworkserviceenabled <networkservice> <on off>
    Set <networkservice> to either <on> or <off> (enabled or disabled).

Usage: networksetup -createnetworkservice <newnetworkservicename> <hardwareport>
    Create a service named <networkservice> on port <hardwareport>. The new service will be enabled by default.

Usage: networksetup -renamenetworkservice <networkservice> <newnetworkservicename>
    Rename <networkservice> to <newnetworkservicename>.

Usage: networksetup -duplicatenetworkservice <networkservice> <newnetworkservicename>
    Duplicate <networkservice> and name it with <newnetworkservicename>.

Usage: networksetup -removenetworkservice <networkservice>
    Remove the service named <networkservice>. Will fail if this is the only service on the hardware port that <networkservice> is on.

Usage: networksetup -ordernetworkservices <service1> <service2> <service3> <...>
    Order the services in order specified. Use "-listnetworkserviceorder" to view service order.
    Note: use quotes around service names which contain spaces (ie. "Built-in Ethernet").

Usage: networksetup -setMTUAndMediaAutomatically <hardwareport or device name>
    Set hardwareport or device specified back to automatically setting the MTU and Media.

Usage: networksetup -getMTU <hardwareport or device name>
    Get the MTU value for hardwareport or device specified.

Usage: networksetup -setMTU <hardwareport or device name> <value>
    Set MTU for hardwareport or device specified.

Usage: networksetup -listvalidMTUrange <hardwareport or device name>
    List the valid MTU range for hardwareport or device specified.

Usage: networksetup -getmedia <hardwareport or device name>
    Show both the current setting for media and the active media on hardwareport or device specified.

Usage: networksetup -setmedia <hardwareport or device name> <subtype> [option1] [option2] [...]
    Set media for hardwareport or device specified to subtype. Specify optional [option1] and additional options depending on subtype. Any number of valid options can be specified.

Usage: networksetup -listvalidmedia <hardwareport or device name>
     List valid media options for hardwareport or device name. Enumerates available subtypes and options per subtype.

Usage: networksetup -createVLAN <VLAN name> <device name> <tag>
    Create a VLAN with name <VLAN name> over device <device name> with unique tag <tag>. A default network service will be created over the VLAN.

Usage: networksetup -deleteVLAN <VLAN name> <device name> <tag>
    Delete the VLAN with name <VLAN name> over the parent device <device name> with unique tag <tag>. If there are network services running over the VLAN they will be deleted.

Usage: networksetup -listVLANs
    List the VLANs that have been created.

Usage: networksetup -listdevicesthatsupportVLAN
    List the devices that support VLANs.

Usage: networksetup -isBondSupported <device name ie., en0>
    Return YES if the specified device can be added to a bond. NO if it cannot.

Usage: networksetup -createBond <user defined name> <device name 1> <device name 2> <...>
    Create a new bond and give it the user defined name. Add the specified devices, if any, to the bond.

Usage: networksetup -deleteBond <bond name ie., bond0>
    Delete the bond with the specified device-name.

Usage: networksetup -addDeviceToBond <device name> <bond name>
    Add the specified device to the specified bond.

Usage: networksetup -removeDeviceFromBond <device name> <bond name>
    Remove the specified device from the specified bond

Usage: networksetup -listBonds
    List all of the bonds.

Usage: networksetup -showBondStatus <bond name ie., bond0>
    Display the status of the specified bond.

Usage: networksetup -listpppoeservices
    List all of the PPPoE services in the current set.

Usage: networksetup -showpppoestatus <service name ie., MyPPPoEService>
    Display the status of the specified PPPoE service.

Usage: networksetup -createpppoeservice <device name ie., en0> <service name> <account name> <password> [pppoe service name]
    Create a PPPoE service on the specified device with the service name specified.
    The "pppoe service name" is optional and may not be supported by the service provider.

Usage: networksetup -deletepppoeservice <service name>
    Delete the PPPoE service.

Usage: networksetup -setpppoeaccountname <service name> <account name>
    Sets the account name for the specified service.

Usage: networksetup -setpppoepassword <service name> <password>
    Sets the password stored in the keychain for the specified service.

Usage: networksetup -connectpppoeservice <service name>
    Connect the PPPoE service.

Usage: networksetup -disconnectpppoeservice <service name>
    Disconnect the PPPoE service.

Usage: networksetup -getcurrentlocation
    Display the name of the current location.

Usage: networksetup -listlocations
    List all of the locations.

Usage: networksetup -createlocation <location name> [populate]
    Create a new network location with the spcified name.
    If the optional term "populate" is included, the location will be populated with the default services.

Usage: networksetup -deletelocation <location name>
    Delete the location.

Usage: networksetup -switchtolocation <location name>
    Make the specified location the current location.

Usage: networksetup -listalluserprofiles
    Display the names of all of the user profiles.

Usage: networksetup -listloginprofiles <service name>
    Display the names of the loginwindow profiles for the specified service.

Usage: networksetup -enablesystemprofile <service name> <on off>
    Enables or disables the system profile for the specified service.

Usage: networksetup -enableloginprofile <service name> <profile name> <on off>
    Enables or disables the specified loginwindow profile for the specified service.

Usage: networksetup -enableuserprofile <profile name> <on off>
    Enables or disables the specified user profile.

Usage: networksetup -import8021xProfiles <service name> <file path>
    Imports the 802.1x profiles for the specified service.

Usage: networksetup -export8021xProfiles <service name> <file path> <include keychain items: yes no>
    Exports all of the profiles for the specified service.
    If the last parameter is yes, it will include the items from the keychain.

Usage: networksetup -export8021xUserProfiles <file path> <include keychain items: yes no>
    Exports only the user profiles.

    If the last parameter is yes, it will include the items from the keychain.

Usage: networksetup -export8021xLoginProfiles <service name> <file path> <include keychain items: yes no>
    Exports only the loginwindow profiles for the specified service.

    If the last parameter is yes, it will include the items from the keychain.

Usage: networksetup -export8021xSystemProfile <service name> <file path> <include keychain items: yes no>
    Exports only the system profile for the specified service.

    If the last parameter is yes, it will include the items from the keychain.

Usage: networksetup -settlsidentityonsystemprofile <service name> <file path> <passphrase>
    Sets the TLS identity on the system profile for the specified service.

    The identity must be a pkcs12 file.

Usage: networksetup -settlsidentityonuserprofile <profile name> <file path> <passphrase>
    Sets the TLS identity on the specified user profile.

    The identity must be a pkcs12 file.

Usage: networksetup -deletesystemprofile <service name>
    Deletes the system profile for the specified service.

Usage: networksetup -deleteloginprofile <service name> <profile name>
    Deletes the specified loginwindow profile for the specified service.

Usage: networksetup -deleteuserprofile <profile name>
    Deletes the specified user profile.

Usage: networksetup -version
    Display version of networksetup tool.

Usage: networksetup -help
    Display these help listings.

Usage: networksetup -printcommands
    Displays a quick listing of commands (without explanations).

Any command that takes a password, will accept - to indicate the password should be read from stdin.
```

### systemsetup

This utility provides a lot of simpler system setup options.

```text
$ sudo /usr/sbin/systemsetup
systemsetup Help Information
-------------------------------------
Usage: systemsetup -getdate
    Display current date.

Usage: systemsetup -setdate <mm:dd:yy>
    Set current date to <mm:dd:yy>.

Usage: systemsetup -gettime
    Display current time.

Usage: systemsetup -settime <hh:mm:ss>
    Set current time to <hh:mm:ss>.

Usage: systemsetup -gettimezone
    Display current time zone.

Usage: systemsetup -settimezone <timezone>
    Set current time zone to <timezone>. Use "-listtimezones" to list time zones.

Usage: systemsetup -listtimezones
    List time zones supported by this machine.

Usage: systemsetup -getusingnetworktime
    Display whether network time is on or off.

Usage: systemsetup -setusingnetworktime <on off>
    Set using network time to either <on> or <off>.

Usage: systemsetup -getnetworktimeserver
    Display network time server.

Usage: systemsetup -setnetworktimeserver <timeserver>
    Set network time server to <timeserver>.

Usage: systemsetup -getsleep
    Display amount of idle time until computer, display and hard disk sleep.

Usage: systemsetup -setsleep <minutes>
    Set amount of idle time until computer, display and hard disk sleep to <minutes>.
    Specify "Never" or "Off" for never.

Usage: systemsetup -getcomputersleep
    Display amount of idle time until computer sleeps.

Usage: systemsetup -setcomputersleep <minutes>
    Set amount of idle time until compputer sleeps to <minutes>.
    Specify "Never" or "Off" for never.

Usage: systemsetup -getdisplaysleep
    Display amount of idle time until display sleeps.

Usage: systemsetup -setdisplaysleep <minutes>
    Set amount of idle time until display sleeps to <minutes>.
    Specify "Never" or "Off" for never.

Usage: systemsetup -getharddisksleep
    Display amount of idle time until hard disk sleeps.

Usage: systemsetup -setharddisksleep <minutes>
    Set amount of idle time until hard disk sleeps to <minutes>.
    Specify "Never" or "Off" for never.

Usage: systemsetup -getwakeonmodem
    Display whether wake on modem is on or off.

Usage: systemsetup -setwakeonmodem <on off>
    Set wake on modem to either <on> or <off>.

Usage: systemsetup -getwakeonnetworkaccess
    Display whether wake on network access is on or off.

Usage: systemsetup -setwakeonnetworkaccess <on off>
    Set wake on network access to either <on> or <off>.

Usage: systemsetup -getrestartpowerfailure
    Display whether restart on power failure is on or off.

Usage: systemsetup -setrestartpowerfailure <on off>
    Set restart on power failure to either <on> or <off>.

Usage: systemsetup -getrestartfreeze
    Display whether restart on freeze is on or off.

Usage: systemsetup -setrestartfreeze <on off>
    Set restart on freeze to either <on> or <off>.

Usage: systemsetup -getallowpowerbuttontosleepcomputer
    Display whether the power button is able to sleep the computer.

Usage: systemsetup -setallowpowerbuttontosleepcomputer <on off>
    Enable or disable whether the power button can sleep the computer.

Usage: systemsetup -getremotelogin
    Display whether remote login is on or off.

Usage: systemsetup -setremotelogin <on off>
    Set remote login to either <on> or <off>. Use "systemsetup -f -setremotelogin off" to suppress prompting when turning remote login off. Requires Full Disk Access privileges.

Usage: systemsetup -getremoteappleevents
    Display whether remote apple events are on or off.

Usage: systemsetup -setremoteappleevents <on off>
    Set remote apple events to either <on> or <off>. Requires Full Disk Access privileges.

Usage: systemsetup -getcomputername
    Display computer name.

Usage: systemsetup -setcomputername <computername>
    Set computer name to <computername>.

Usage: systemsetup -getlocalsubnetname
    Display local subnet name.

Usage: systemsetup -setlocalsubnetname <name>
    Set local subnet name to <name>.

Usage: systemsetup -getstartupdisk
    Display current startup disk.

Usage: systemsetup -setstartupdisk <disk>
    Set current startup disk to <disk>.

Usage: systemsetup -liststartupdisks
    List startup disks on this machine.

Usage: systemsetup -getwaitforstartupafterpowerfailure
    Get the number of seconds after which the computer will start up after a power failure.

Usage: systemsetup -setwaitforstartupafterpowerfailure <seconds>
    Set the number of seconds after which the computer will start up after a power failure. The <seconds> value must be a multiple of 30 seconds.

Usage: systemsetup -getdisablekeyboardwhenenclosurelockisengaged
     Get whether or not the keyboard should be disabled when the X Serve enclosure lock is engaged.

Usage: systemsetup -setdisablekeyboardwhenenclosurelockisengaged <yes no>
     Set whether or not the keyboard should be disabled when the X Serve enclosure lock is engaged.

Usage: systemsetup -version
    Display version of systemsetup tool.

Usage: systemsetup -help
    Display help.

Usage: systemsetup -printCommands
    Display commands.
```

### airport

The Airport command-line utility can yield a lot of useful Wi-Fi info.

```text
$ /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
Usage: airport <interface> <verb> <options>

    <interface>
    If an interface is not specified, airport will use the first AirPort interface on the system.

    <verb is one of the following:
    prefs    If specified with no key value pairs, displays a subset of AirPort preferences for
        the specified interface.

        Preferences may be configured using key=value syntax. Keys and possible values are specified below.
        Boolean settings may be configured using 'YES' and 'NO'.

        DisconnectOnLogout (Boolean)
        JoinMode (String)
            Automatic
            Preferred
            Ranked
            Recent
            Strongest
        JoinModeFallback (String)
            Prompt
            JoinOpen
            KeepLooking
            DoNothing
        RememberRecentNetworks (Boolean)
        RequireAdmin (Boolean)
        RequireAdminIBSS (Boolean)
        RequireAdminNetworkChange (Boolean)
        RequireAdminPowerToggle (Boolean)
        WoWEnabled (Boolean)

    logger    Monitor the driver's logging facility.

    sniff    If a channel number is specified, airportd will attempt to configure the interface
        to use that channel before it begins sniffing 802.11 frames. Captures files are saved to /tmp.
        Requires super user privileges.

    debug    Enable debug logging. A debug log setting may be enabled by prefixing it with a '+', and disabled
        by prefixing it with a '-'.

        AirPort Userland Debug Flags
            DriverDiscovery
            DriverEvent
            Info
            SystemConfiguration
            UserEvent
            PreferredNetworks
            AutoJoin
            IPC
            Scan
            802.1x
            Assoc
            Keychain
            RSNAuth
            WoW
            P2P
            Roam
            BTCoex
            AllUserland - Enable/Disable all userland debug flags

        AirPort Driver Common Flags
            DriverInfo
            DriverError
            DriverWPA
            DriverScan
            AllDriver - Enable/Disable all driver debug flags

        AirPort Driver Vendor Flags
            VendorAssoc
            VendorConnection
            AllVendor - Enable/Disable all vendor debug flags

        AirPort Global Flags
            LogFile - Save all AirPort logs to /var/log/wifi.log

<options> is one of the following:
    No options currently defined.

Examples:

Configuring preferences (requires admin privileges)
    sudo airport en1 prefs JoinMode=Preferred RememberRecentNetworks=NO RequireAdmin=YES

Sniffing on channel 1:
    airport en1 sniff 1


LEGACY COMMANDS:
Supported arguments:
 -c[<arg>] --channel=[<arg>]    Set arbitrary channel on the card
 -z        --disassociate       Disassociate from any network
 -I        --getinfo            Print current wireless status, e.g. signal info, BSSID, port type etc.
 -s[<arg>] --scan=[<arg>]       Perform a wireless broadcast scan.
                   Will perform a directed scan if the optional <arg> is provided
 -x        --xml                Print info as XML
 -P        --psk                Create PSK from specified pass phrase and SSID.
                   The following additional arguments must be specified with this command:
                                  --password=<arg>  Specify a WPA password
                                  --ssid=<arg>      Specify SSID when creating a PSK
 -h        --help               Show this help

```

Probably my favorite use of this command is getting the current network:

```text
$ /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
     agrCtlRSSI: -40
     agrExtRSSI: 0
    agrCtlNoise: -91
    agrExtNoise: 0
          state: running
        op mode: station
     lastTxRate: 351
        maxRate: 1300
lastAssocStatus: 0
    802.11 auth: open
      link auth: wpa2-psk
          BSSID: MY_BSSID
           SSID: MY_SSID
            MCS: 7
        channel: 44,80
```

Also, you can scan your local Wi-Fi networks by running:

```text
$ /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
... Networks Here ...
```

### AssetCacheLocatorUtil

This tool fetches the available Content Caches available to your machine, and other Apple devices on the network.
Content Cache is available in Sharing inside System Preferences and allows you to cache System Updates and iCloud content on local machines for bandwidth reduction.

```text
$ /usr/bin/AssetCacheLocatorUtil
kendfinger@KenMac MacHack % /usr/bin/AssetCacheLocatorUtil
2020-12-26 20:35:24.351 AssetCacheLocatorUtil[39485:7741115] AssetCacheLocatorUtil version 116, framework version 116
2020-12-26 20:35:24.351 AssetCacheLocatorUtil[39485:7741115] Determining public IP address...
2020-12-26 20:35:24.494 AssetCacheLocatorUtil[39485:7741115] This computer's public IP address is 8.30.97.117.
2020-12-26 20:35:24.494 AssetCacheLocatorUtil[39485:7741115] --- Information for system services:
.... More Output
```

The output from this command is pretty large but it will allow you to diagnose access to content cache.

### AssetCacheManagerUtil

This tool manages the Content Cache service on your machine.

```text
$ /usr/bin/AssetCacheManagerUtil   
2020-07-04 01:26:37.394 AssetCacheManagerUtil[2835:949425] Usage: AssetCacheManagerUtil [options] command
2020-07-04 01:26:37.394 AssetCacheManagerUtil[2835:949425] Options are:
    -a|--all        show all events
    -j|--json       print results in JSON
    -l|--linger     don't exit
2020-07-04 01:26:37.394 AssetCacheManagerUtil[2835:949425] Commands are:
    activate
    deactivate
    isActivated
    canActivate
    flushCache
    flushPersonalCache
    flushSharedCache
    status
    settings
    reloadSettings
    moveCacheTo path
    absorbCacheFrom path read-only|and-destroy
```

An example usage of this command is:

```text
$ /usr/bin/AssetCacheManagerUtil status   
2020-07-04 01:29:24.546 AssetCacheManagerUtil[3572:955073] Content caching status:
    Activated: false
    Active: false
    CacheDetails: (none)
    CacheFree: 293.24 GB
    CacheLimit: unlimited
    CacheStatus: OK
    CacheUsed: Zero KB
    Parents: (none)
    Peers: (none)
    PersonalCacheFree: 293.24 GB
    PersonalCacheLimit: unlimited
    PersonalCacheUsed: Zero KB
    Port: 0
    RegistrationError: NOT_ACTIVATED
    RegistrationResponseCode: 403
    RegistrationStatus: -1
    RestrictedMedia: false
    ServerGUID: [GUID HERE]
    StartupStatus: FAILED
    TetheratorStatus: 0
    TotalBytesAreSince: 2020-07-03 17:22:37
    TotalBytesDropped: Zero KB
    TotalBytesImported: Zero KB
    TotalBytesReturnedToChildren: Zero KB
    TotalBytesReturnedToClients: Zero KB
    TotalBytesReturnedToPeers: Zero KB
    TotalBytesStoredFromOrigin: Zero KB
    TotalBytesStoredFromParents: Zero KB
    TotalBytesStoredFromPeers: Zero KB
```

### seedutil

seedutil allows you to enroll and un-enroll from AppleSeed programs, such as Public Betas.

```text
$ sudo /System/Library/PrivateFrameworks/Seeding.framework/Resources/seedutil
usage: seedutil enroll SEED_PROGRAM
       seedutil unenroll
       seedutil current
       seedutil migrate OLD_VERSION NEW_VERSION
       seedutil fixup
```

An example usage of this command is:

```text
$ sudo /System/Library/PrivateFrameworks/Seeding.framework/Resources/seedutil current
Currently enrolled in: (null)

Program: 0
Build is seed: NO
CatalogURL: (null)
NSShowFeedbackMenu: NO
DisableSeedOptOut: NO
Asset Audience: c80fd46d-7cc7-487e-993c-3876697879dc
```

### kmutil

kmutil is a tool for managing Kernel Extensions.

```text
$ kmutil
OVERVIEW: kmutil: KernelManagement Utility (KernelManagement_executables-102.60.20)

USAGE: kmutil <subcommand>

OPTIONS:
  -h, --help              Show help information.

SUBCOMMANDS:
  create                  Create one or more new artifacts based on the arguments provided.
  load                    Load one or more extensions based on the arguments provided.
  unload                  Unload the named kexts and all personalities.
  log                     Display logging information about the KernelManagement subsystem.
  libraries               Search for library kexts that define symbols needed for linking by a a kernel extension.
  dumpstate               Dumps kernelmanagerd(8) state for debugging
  inspect                 Inspect & display a kext collection's contents according to the options provided.
  clear-staging           Clears all contents of the kext staging locations on the system
  find                    Find kexts available on the operating system.
  showloaded              Show the loaded state of the extensions on the system, according to the options provided.
  trigger-panic-medic     Delete and disable loading of third party kexts in order to safely boot into a target volume. (can only be triggered in Recovery mode)
                          eg usage: `kmutil trigger-panic-medic --volume-root /Volumes/<VolumeName>`
  check                   Check the consistency of kext collections against each other and/or load information in-kernel.
  print-diagnostics       Perform all possible tests on a specified kext, and indicate whether the kext is loadable.

  See 'kmutil help <subcommand>' for detailed help.
```

An example of using kmutil is to list loaded kexts:

```text
$ kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  139 0                  0          0          com.apple.kpi.bsd (20.2.0) 82E2050C-5936-3D24-AD3B-EC4EC5C09E11 <>
    2   11 0                  0          0          com.apple.kpi.dsep (20.2.0) 82E2050C-5936-3D24-AD3B-EC4EC5C09E11 <>
    3  168 0                  0          0          com.apple.kpi.iokit (20.2.0) 82E2050C-5936-3D24-AD3B-EC4EC5C09E11 <>
    4    0 0                  0          0          com.apple.kpi.kasan (20.2.0) 82E2050C-5936-3D24-AD3B-EC4EC5C09E11 <>
```

### profiles

profiles allows you to manage and inspect macOS profiles. This is most commonly used for MDM.

```text
$ profiles help
profiles allows you access configuration or application provisioning profiles on macOS.
    Use 'profiles help' for this help section, or use the man page for expanded instructions.
    Basic usage is in the form:  'profiles <command verb> [<options and parameters>]'

    Clients should use the Profiles System Preferences pane to install configuration profiles.

    Command Verbs:
                    status - indicates if profiles are installed
                    list - list profile information
                    show - show expanded profile information
                    remove - remove profile
                    sync - synchronize installed configuration profiles with known users
                    renew - renew configuration profile installed certificate
                    validate - validation of provisioning profile or DEP server enrollment information
                    version - display tool version number

    Options:    (not all options are meaningful for a command)
                    -type=<string> - type of profile; either 'configuration', 'provisioning', 'enrollment', or 'bootstraptoken'
                    -user=<string> - short user name
                    -password=<string> - password
                    -identifier=<string> - profile identifier
                    -path=<string> - file path
                    -uuid=<string> - profile UUID
                    -enrolledUser=<string> - enrolled user name
                    -verbose - enable verbose mode
                    -forced - when removing profiles, automatically confirms requests
                    -all - select all profiles
                    -quiet - enable quiet mode
```

An example usage of profiles is viewing the status of profile enrollment:

```text
$ profiles status -type enrollment
Enrolled via DEP: No
MDM enrollment: No
```

### bputil

bputil is a tool for managing Boot Policy. This tool is only available on Apple Silicon. If you run this tool on x86_64, it will output: `bputil is not yet supported on this platform.`

```text
$ bputil

This utility is not meant for normal users or even sysadmins.
It provides unabstracted access to capabilities which are normally handled for the user automatically when changing the security policy through GUIs such as Startup Disk in macOS Recovery.
It is possible to make your system security much weaker and therefore easier to compromise using this tool.
This tool is not to be used in production environments.
It is possible to render your system unbootable with this tool.
It should only be used to understand how the security of Apple Silicon Macs works.
Use at your own risk!

bputil v0.1.3 - a tool to modify boot policies
        bputil <optional arguments> ...

    Optional arguments:
    -u, --username <username>
        Used to specify the username for a user with access to the signing key to authenticate the change
        If this is specified, the below password option is required too
        If this is not specified, an interactive prompt will request the username
    -p, --password <password>
        Used to specify the password for a user with access to the signing key to authenticate the change
        If this is specified, the above username option is required too
        If this is not specified, an interactive prompt will request the password
    -v, --vuid <AABBCCDD-EEFF-0011-2233-445566778899>
        Set the Volume Group UUID value
        If no option is specified, the default value of Volume Group UUID will be set to the APFS volume group UUID of the running OS
        Volume Group UUID for a given OS can be found with 'diskutil apfs listVolumeGroups'
    -l, --debug-logging
        Enables verbose logging to assist in debugging any issues associated with changing the policy
    -d, --display-policy
        Display the local policy. If the system has multiple bootable volumes, an interactive prompt will ask you to specify a volume
    -f, --full-security
        Changes security mode to Full Security. This option is mutually exclusive with all options below which cause security downgrades
    -g, --reduced-security
        Changes security mode to Reduced Security
        Passing this option will explicitly recreate the LocalPolicy, only the options specified via this tool will exist in the output local policy
    -n, --permissive-security
        Changes security mode to Permissive Security
        Passing this option will explicitly recreate the LocalPolicy, only the options specified via this tool will exist in the output local policy
    -m, --enable-mdm
        Enables MDM management of software updates & kernel extensions
        Automatically downgrades to Reduced Security mode if not already true
    -k, --enable-kexts
        Enables trust in locally SEP-signed AuxilaryKernelCache that contains 3rd party kexts
        Automatically downgrades to Reduced Security mode if not already true
    -c, --disable-kernel-ctrr
        Disables the enforcement of the Configurable Text Read-only Region that protects Kernel code
        Automatically downgrades to Permissive Security mode if not already true
    -a, --disable-boot-args-restriction
        Enables sending custom boot args to the kernel
        Automatically downgrades to Permissive Security mode if not already true
    -s, --disable-ssv
        Disables Signed System Volume integrity checks
        Automatically downgrades to Permissive Security mode if not already true
        NOTE: SSV cannot be disabled while FileVault is enabled
```
