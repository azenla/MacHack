# MacHack

A list of built-in tools in macOS that you probably didn't know about.

## SafeEjectGPU (GPUs)

This is a utility for managing GPUs, especially eGPUs. This is what is behind
the safe eject functionality of the eGPU in the System UI.

It is useful for:

* Listing GPUs on the system.
* Determining what applications are using a particular GPU.
* Ejecting an eGPU safely.
* Launching an application on a specific GPU.
* Switching an application from one GPU to another.

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

## remotectl (Bridge Chips)

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

## brctl

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

## sysadminctl

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

## ckkctl

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

## otctl

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
$ /us/sbin/otctl status
... Lots of Useful Output ...
```

## spctl

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
