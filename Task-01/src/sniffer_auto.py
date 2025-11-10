# sniffer_auto.py
import argparse, time, os
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap, get_if_list

# -----------------------------
# Setup captures folder
# -----------------------------
CAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures")
os.makedirs(CAP_DIR, exist_ok=True)

# -----------------------------
# Packet counters
# -----------------------------
packet_count = 0
tcp_count = 0
udp_count = 0
http_count = 0
https_count = 0
captured_packets = []

# -----------------------------
# Packet summary function
# -----------------------------
def packet_summary(pkt):
    global packet_count, tcp_count, udp_count, http_count, https_count, captured_packets
    packet_count += 1
    captured_packets.append(pkt)
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt.time))
    src = pkt[IP].src if IP in pkt else "N/A"
    dst = pkt[IP].dst if IP in pkt else "N/A"
    info = f"[{ts}] {src} -> {dst}"
    if TCP in pkt:
        tcp_count += 1
        info += f" TCP {pkt[TCP].sport}->{pkt[TCP].dport}"
        if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
            http_count += 1
        if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
            https_count += 1
    elif UDP in pkt:
        udp_count += 1
        info += f" UDP {pkt[UDP].sport}->{pkt[UDP].dport}"
    # small payload preview
    if Raw in pkt:
        preview = pkt[Raw].load[:80]
        try:
            preview_text = preview.decode(errors='replace')
        except:
            preview_text = str(preview)
        info += f" | payload: {preview_text!r}"
    print(info)

# -----------------------------
# Save captured packets
# -----------------------------
def save_and_report(suffix="final"):
    global captured_packets, packet_count, tcp_count, udp_count, http_count, https_count
    if captured_packets:
        fname = os.path.join(CAP_DIR, f"capture_{suffix}_{int(time.time())}.pcap")
        wrpcap(fname, captured_packets)
        print(f"\nSaved {len(captured_packets)} packets to: {fname}")
    else:
        print("\nNo packets were captured.")
    print(f"Totals: packets={packet_count}, tcp={tcp_count}, udp={udp_count}, http={http_count}, https={https_count}")

# -----------------------------
# Main function
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Auto-stopping Python network sniffer (Windows)")
    parser.add_argument("--iface", help="Interface name (e.g. \\Device\\NPF_{...})", default=None)
    parser.add_argument("--filter", help="BPF filter (e.g. 'tcp port 80 or tcp port 443')", default="tcp port 80 or tcp port 443")
    parser.add_argument("--count", type=int, help="Capture this many packets then stop", default=None)
    parser.add_argument("--timeout", type=int, help="Capture for this many seconds then stop (default 60 if no count)", default=60)
    args = parser.parse_args()

    interfaces = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    use_iface = args.iface or interfaces[0]
    print(f"\nUsing interface: {use_iface}")
    print(f"Filter: {args.filter!r}")
    print("Starting capture... (will auto-stop based on --count or --timeout)")

    try:
        if args.count:
            sniff(iface=use_iface, filter=args.filter, prn=packet_summary, count=args.count)
        else:
            sniff(iface=use_iface, filter=args.filter, prn=packet_summary, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nStopped by user (KeyboardInterrupt).")
    except Exception as e:
        print("Error while sniffing:", e)

    # save and print summary
    save_and_report(suffix=("count" if args.count else f"time{args.timeout}"))

if __name__ == "__main__":
    main()
