def check_missing_packets(packets, total):
    missing_packets = []
    for i in range(0, total):
        if not packets.get(i):
            missing_packets.append(i)
    return missing_packets if len(missing_packets) > 0 else None