from scapy.all import IP, ICMP, send, sr
import os
import time
import struct
import sys


def make_ip(i):
    decimal_ip = 3232246530 + i
    new_address = ''

    binary_ip = format(decimal_ip, '032b')
    octet = ''
    for i in range(0, 32):
        if i % 8 == 0 and i != 0:
            new_address += str(int(octet, 2)) + '.'
            octet = ''
        octet += binary_ip[i]
        
    new_address += str(int(octet, 2))
    return new_address[:32]       


# Функция для создания и отправки пакета
def send_icmp_packet(destination_ip, source_ip, i):
    start_time = time.time()  # засекаем время и записываем его в поле данных пакета
    packet = IP()/ICMP()/struct.pack('d', start_time)

    packet[IP].dst = destination_ip
    packet[IP].src = source_ip
    packet[IP].id = os.getpid() & 0xFFFF
    packet[ICMP].seq = i
    packet[ICMP].id = os.getpid() & 0xFFFF
    packet[ICMP].chksum = None

    print(f"{i}){source_ip}")
    sr(packet, timeout=0.1, verbose=False)


if __name__ == "__main__":
    # [192.168.43.1 8.8.8.8]
    dest = sys.argv[1]
    i = 0
    while True:
        i += 1
        send_icmp_packet(dest, make_ip(i), i)
        if i == 4294967200:
            i = 0
        # time.sleep(0.1)
