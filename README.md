
    # -Raspberry-Pi-sudo apt install python3-pip--run
    -git install run
    sudo pip3 install scapy-run
    # drone_rid_sniffer.py
    from scapy.all import sniff, Dot11Beacon, Dot11EltVendorSpecific

    <VENDOR_PREFIX> = b"\xfa\x0b"  # ตัวอย่าง prefix ของ vendor-specific IE; ต้องตรวจกับมาตรฐาน/ผู้ผลิตจริง

    def handle(pkt):main
    if not pkt.haslayer(Dot11Beacon):
        return

    ssid = None
    vendor = []

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:  # SSID
            ssid = elt.info.decode(errors="ignore")
        elif elt.ID == 221:  # Vendor Specific
            vendor.append(bytes(elt.info))
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    if any(v.startswith(VENDOR_PREFIX) for v in vendor):
        print({
            "time": pkt.time,
            "ssid": ssid,
            "source_mac": pkt.addr2,
            "rssi_dbm": getattr(pkt, "dBm_AntSignal", None),
            "vendor_ie": [v.hex() for v in vendor],
        })

    if __name__ == "__main__":
    # เปลี่ยนเป็นอินเทอร์เฟซ monitor mode เช่น wlan0mon
    sniff(iface="wlan0mon", prn=handle, store=False)
    sudo airmon-ng check kill
    sudo airmon-ng start wlan0
    sudo python3 drone_rid_sniffer.py
    build git 