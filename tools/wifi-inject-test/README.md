# Wi-Fi monitor injection test

This is a passive evidence collector. It does not change Wi-Fi mode or transmit anything.

## Test procedure

1. Flash and boot the kernel built from the branch under test.
2. Enable monitor mode and set the interface to the same channel used by the test transmitter.
3. Start the beacon test from a separate shell, for example:

   `mdk4 wlan0 b -n KEBAB_TEST_ONLY -c 6 -s 1`

4. While the test is running, execute the collector as root:

   `sh tools/wifi-inject-test/collect.sh`

5. Read `/data/local/tmp/wifi-inject-test/summary.txt` and `dmesg-injection.txt`.

## What counts as evidence

- `Injection monitor: accepted by CDP/HTT datapath` means the host datapath accepted the frame. It does not prove that the firmware transmitted it over the air.
- A visible SSID or captured beacon on a second independent Wi-Fi receiver, fixed to the same channel, is the OTA confirmation.
- The mdk4 `Packets sent` counter is not OTA confirmation.
- If there is no CDP acceptance log, the captured state and full dmesg help identify whether the request reached the patched path.

Do not use the phone's own scan result as the only OTA check while its interface is in monitor mode.
