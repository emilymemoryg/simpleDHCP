from socket import *
import struct
from uuid import getnode
from random import randint
import binascii

#change
def getMacAddress():
    mac = hex(getnode())
    mac = mac[2:]
    printMac = mac[:2]
    for i in range(2,12,2):
            printMac += ":" + mac[i:i+2]
    print("Mac Address: " + printMac)
    macBytes = b''
    macBytes = binascii.unhexlify(mac)
    return macBytes
class DHCPDiscover:
    def __init__(self):
        self.xid = b''
        self.mac = b''
        for i in range(4):
            t = randint(0, 255)
            self.xid += struct.pack('!B', t)
    def protocolPacket(self):
        packet = bytearray(246)
        packet[0] = 1 #self.message_type
        packet[1] = 1 #self.hardware_type
        packet[2] = 6 #self.hardware_address_length
        packet[3] = 0 #self.hops

        packet[4:8] = self.xid #xid
        packet[ 8:10] = b'\x00\x00' #SECS
        packet[10:12] = b'\x00\x00' #FLAGS

        packet[12:16] = inet_aton('0.0.0.0') #client_ip_address
        packet[16:20] = inet_aton('0.0.0.0') #your_ip_address
        packet[20:24] = inet_aton('0.0.0.0') #next_server_ip_address
        packet[24:28] = inet_aton('0.0.0.0') #relay_agent_ip_address

        packet[28:34] = self.mac = getMacAddress()
        packet[34:44] = b'\x00' * 10
        
        packet[44:236]= b'\x00' * 192
        packet[236:240] =  b'\x63\x82\x53\x63' #Magic Cookie
        #packet[240] = 53 #xid
        #packet[241] = 1
        #packet[242] = 1 #dhcpdiscover
        packet[243:246] =  b'\x35\x01\x01' # Message Type(code=53 len=1 type=1(DHCPDISCOVER))
        packet += b'\x37\x03\x03\x01\x06'
        packet += b'\xff'
        return bytes(packet)
    def unPack(self,data):
        mac = data[28:34]
        print("mac: " + mac)
class DHCPOffer:
    def __init__(self,data,xid):
        self.data = data
        self.xid = xid
        self.offerIP = ''
        self.dhcpServer = ''
        self.nextServerIP = ''
        self.unPack()
    def unPack(self):
        print("------------DHCPOffer-------------")
        if self.data[4:8] == self.xid :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24]))
            self.dhcpServer = '.'.join(map(lambda x:str(x), data[263:267]))
            print("Offer IP: " + '.'.join(map(lambda x:str(x), data[16:20])))
            print("Next Server IP: " + '.'.join(map(lambda x:str(x), data[20:24])))
            print("Subnet Mask:"  + '.'.join(map(lambda x:str(x), data[245:249])))
            print("Router:"  + '.'.join(map(lambda x:str(x), data[251:255])))
            print("lease Time:"  + str(struct.unpack('!i',data[257:261])))
            print("DHCP Server:"  + '.'.join(map(lambda x:str(x), data[263:267])))
            print("DNS server:"  + '.'.join(map(lambda x:str(x), data[269:273])))
            print("DNS server:"  + '.'.join(map(lambda x:str(x), data[275:279])))
            print("DNS server:"  + '.'.join(map(lambda x:str(x), data[281:285])))
class DHCPRequest:
    def __init__(self,xid,mac,nextServerIP,dhcpServer,offerIP):
        self.xid = xid
        self.mac = mac
        self.nextServerIP = nextServerIP
        self.dhcpServer = dhcpServer
        self.offerIP = offerIP
    def protocolPacket(self):
        packet = bytearray(246)
        packet[0] = 1 #self.message_type
        packet[1] = 1 #self.hardware_type
        packet[2] = 6 #self.hardware_address_length
        packet[3] = 0 #self.hops

        packet[4:8] = self.xid #xid
        packet[ 8:10] = b'\x00\x00' #SECS
        packet[10:12] = b'\x00\x00' #FLAGS

        packet[12:16] = inet_aton('0.0.0.0') #client_ip_address
        packet[16:20] = inet_aton('0.0.0.0') #your_ip_address
        packet[20:24] = inet_aton(self.nextServerIP) #next_server_ip_address
        packet[24:28] = inet_aton('0.0.0.0') #relay_agent_ip_address

        packet[28:34] = self.mac
        packet[34:44] = b'\x00' * 10
        packet[44:236]= b'\x00' * 192
        
        packet[236:240] =  b'\x63\x82\x53\x63' #Magic Cookie
        #packet[240] = 53 #xid
        #packet[241] = 1
        #packet[242] = 1 #dhcpdiscover
        packet[243:246] =  b'\x35\x01\x03' # Message Type(code=53 len=1 type=3(DHCPRequest))
        packet[246:248] = b'\x32\x04'
        packet[248:252] = inet_aton(self.offerIP)
        packet[252:254] = b'\x36\x04'
        packet[254:258] = inet_aton(self.dhcpServer)
        packet += b'\xff'
        return bytes(packet)
class DHCPACK:
    def __init__(self,data,xid):
        self.data = data
        self.xid = xid
        self.offerIP = ''
        self.dhcpServer = ''
        self.nextServerIP = ''
        self.unPack()
    def unPack(self):
        print("------------DHCPACK-------------")
        if self.data[4:8] == self.xid :
            print("xid is same")
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24]))
            self.dhcpServer = '.'.join(map(lambda x:str(x), data[263:267]))
            print("Offer IP: " + '.'.join(map(lambda x:str(x), data[16:20])))
            print("Next Server IP: " + '.'.join(map(lambda x:str(x), data[20:24])))
            print("Subnet Mask:"  + '.'.join(map(lambda x:str(x), data[245:249])))
            print("Router:"  + '.'.join(map(lambda x:str(x), data[251:255])))
            print("lease Time:"  + str(struct.unpack('!i',data[257:261])))
            print("DHCP Server:"  + '.'.join(map(lambda x:str(x), data[263:267])))
            print("DNS server:"  + '.'.join(map(lambda x:str(x), data[269:273])))
            print("DNS server:"  + '.'.join(map(lambda x:str(x), data[275:279])))
            print("DNS server:"  + '.'.join(map(lambda x:str(x), data[281:285])))
if __name__ == '__main__':
    dhcps = socket(AF_INET, SOCK_DGRAM)
    dhcps.setsockopt(SOL_SOCKET, SO_BROADCAST, 1) 
    try:
        dhcps.bind(('0.0.0.0', 68))
        print(dhcps)
    except Exception as e:
        print('port 68 in use')
        dhcps.close()
        exit()
    discoverPacket = DHCPDiscover()
    dhcps.sendto(discoverPacket.protocolPacket(), ('<broadcast>', 67))
    
    dhcps.settimeout(20)
    try:
        data = dhcps.recv(1024)
        offerPacket = DHCPOffer(data, discoverPacket.xid)
        requestPacket = DHCPRequest(discoverPacket.xid,discoverPacket.mac,offerPacket.nextServerIP,offerPacket.dhcpServer,offerPacket.offerIP)
        dhcps.sendto(requestPacket.protocolPacket(),('<broadcast>',67))
        data = dhcps.recv(1024)
        ackPacket = DHCPACK(data,discoverPacket.xid)
    except timeout as e:
        print(e)
    
    dhcps.close()   
    
    exit()
        
