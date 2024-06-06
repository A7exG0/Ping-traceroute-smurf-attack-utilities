from scapy.all import IP, ICMP, Raw, sr
import os
import time
import struct
import sys


def send_icmp_packet(destination_ip, i):
    start_time = time.time()
    packet = IP()/ICMP()/struct.pack('d', start_time)

    packet[IP].dst = destination_ip
    packet[IP].id = os.getpid() & 0xFFFF
    packet[IP].ttl = i
    packet[ICMP].seq = i
    packet[ICMP].id = os.getpid() & 0xFFFF

    response, _ = sr(packet, timeout=5, verbose=False)
    return response


def print_result(packet, start_time):
    result_time = time.time() - start_time
    print(
        f"Reply from {packet[IP].src}: bytes={len(packet)}, ttl = {packet[IP].ttl} time={round(result_time * 1000)}ms")
    time.sleep(result_time / 2)  # По условию задачи


def process_packet(packet, start_time):
    if Raw in packet:
        byte_time = packet[Raw].load
        start_time = struct.unpack('d', byte_time)[0]

    print_result(packet, start_time)


if __name__ == "__main__":
    dest = sys.argv[1]
    count = 0
    i = 0

    while True:
        i += 1
        response_pair = send_icmp_packet(dest, i)
        if response_pair: 
            response = response_pair[0][1] 
            if response[IP].src == dest:
                process_packet(response, time.time())
                break  # Выход из цикла, если достигли конечного узла
            else:
                process_packet(response, time.time())
        else:
            print("No reply")

        if i > 30:  
            print("Too many hops, stopping...")
            break
