from scapy.all import IP, ICMP, Raw, sr
import os
import time
import struct
import threading
import sys
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    
# Функция для создания и отправки пакета
def send_icmp_packet(destination_ip, i):
    start_time = time.time() # засекаем время и записываем его в поле данных пакета
    packet = IP()/ICMP()/struct.pack('d', start_time)

    packet[IP].dst = destination_ip
    packet[IP].id = os.getpid() & 0xFFFF
    packet[ICMP].seq = i
    packet[ICMP].id = os.getpid() & 0xFFFF
    packet[ICMP].type = 8
    packet[ICMP].chksum = None
    # packet.show()
    response = sr(packet, timeout=2, verbose=False)
    return response

def process_packet(packet):
    byte_time = packet[Raw].load # считываем из данных время в байтах
    start_time = struct.unpack('d', byte_time)[0] # переводим байты
    result_time = time.time() - start_time
    print(f"Reply from {packet[IP].src}: bytes={len(packet)}, ttl = {packet[IP].ttl} time={round(result_time * 1000)}ms")
    time.sleep(result_time / 2) # по условию

def proc_ping(destination_ip):
    for i in range(1, 5):
        response = send_icmp_packet(destination_ip, i)
        if response:
            process_packet(response[0][1])
        else:
            print('No reply')

if __name__ == "__main__":
    if not is_admin():
        print("Please run this script as an administrator.")
        sys.exit(1)
    # [192.168.43.176]
    destinations = sys.argv[1:]
    threads = []
    for destination_ip in destinations :
        thread = threading.Thread(target=proc_ping, args=(destination_ip,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join() 
