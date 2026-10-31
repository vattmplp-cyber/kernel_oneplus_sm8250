#!/system/bin/sh
# Passive diagnostic collector for the qcacld monitor-injection test.
# Does not change con_mode, transmit frames, or clear the kernel log.

OUT="${1:-/data/local/tmp/wifi-inject-test}"
mkdir -p "$OUT" || exit 1

{
    echo "=== timestamp ==="
    date
    echo
    echo "=== kernel ==="
    uname -a
    echo
    echo "=== con_mode ==="
    if [ -r /sys/module/wlan/parameters/con_mode ]; then
        cat /sys/module/wlan/parameters/con_mode
    else
        echo "unavailable"
    fi
    echo
    echo "=== iw dev ==="
    iw dev 2>&1
    echo
    echo "=== wlan0 link ==="
    ip -s link show wlan0 2>&1
    echo
    echo "=== wlan0 wireless info ==="
    iw dev wlan0 info 2>&1
    echo
    echo "=== phy capabilities ==="
    iw phy phy0 info 2>&1
} > "$OUT/state.txt"

dmesg > "$OUT/dmesg-full.txt" 2>&1
grep -iE 'Injection monitor|Injection TX vdev|CDP|HTT|mgmt.*(tx|drop|fail)|wmi.*(mgmt|tx)|frame.inject' \
    "$OUT/dmesg-full.txt" > "$OUT/dmesg-injection.txt" 2>/dev/null

{
    echo "=== collected files ==="
    ls -l "$OUT"
    echo
    echo "=== injection-related kernel messages ==="
    if [ -s "$OUT/dmesg-injection.txt" ]; then
        cat "$OUT/dmesg-injection.txt"
    else
        echo "No matching messages found."
    fi
    echo
    echo "=== interpretation ==="
    echo "CDP/HTT accepted means the host datapath accepted the frame; it does NOT prove OTA transmission."
    echo "Confirm beacon reception with a second independent Wi-Fi adapter/device."
} > "$OUT/summary.txt"

echo "Saved diagnostics to: $OUT"
cat "$OUT/summary.txt"
