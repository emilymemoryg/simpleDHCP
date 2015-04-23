import struct
from uuid import getnode
from random import randint
import binascii
from socket import *

def convertBytes(value,length):
    valueString = hex(value)
    valueString = valueString[2:]
    while len(valueString) < length*2 :
        valueString = '0' + valueString
    valueBytes = b''
    valueBytes = binascii.unhexlify(valueString)
    return valueBytes
    
def getMacAddress():
    mac = hex(getnode())
    mac = mac[2:]
    macBytes = b''
    macBytes = binascii.unhexlify(macAddress)
    return macbytes
    
class DHCPDiscover:
    def __init__(self,data):
        self.xid = b''
        self.mac = b''
        self.data = data
        self.unPack()
    def unPack(self):
        print("------------DHCPDiscover-------------")
        self.mac = self.data[28:34]
        self.xid = self.data[4:8]

        unpackmac = str(binascii.hexlify(self.data[28:34]))
        print(str(unpackmac[2:14]))
        unpackmac = unpackmac[2:14]
        printMAC = unpackmac[0:2]
        for i in range(2,12,2):
            printMAC += ":" + unpackmac[i:i+2]

    #return ['.'.join(map(str, data[i:i + 4])) for i in range(0, len(data), 4)]

        
        print("Client MAC:" + printMAC)
        #print("Client MAC:" + str(binascii.hexlify(self.data[28:34])))
        #print("XID:" + str(struct.unpack('>i',data[4:8])) )
        #print("XID:" + str(binascii.hexlify(self.data[4:8])))
class DHCPOffer:
    def __init__(self,xid,mac,OfferIP,nextServerIP,subnetMask,router,leaseTime,DHCPServer,DNS1,DNS2,DNS3):
        self.xid = xid
        self.mac = mac
        self.OfferIP =OfferIP
        self.nextServerIP = nextServerIP
        self.subnetMask = subnetMask
        self.router = router
        self.leaseTime = leaseTime
        self.DHCPServer = DHCPServer
        self.DNS1 = DNS1
        self.DNS2 = DNS2
        self.DNS3 = DNS3
    def protocolPacket(self):
        packet = bytearray(246)
        packet[0] = 2 #self.message_type
        packet[1] = 1 #self.hardware_type
        packet[2] = 6 #self.hardware_address_length
        packet[3] = 0 #self.hops

        packet[4:8] = self.xid #xid
        packet[ 8:10] = b'\x00\x00' #SECS
        packet[10:12] = b'\x00\x00' #FLAGS

        packet[12:16] = inet_aton('0.0.0.0') #client_ip_address
        packet[16:20] = inet_aton(self.OfferIP) #your_ip_address
        packet[20:24] = inet_aton(self.nextServerIP) #next_server_ip_address
        packet[24:28] = inet_aton('0.0.0.0') #relay_agent_ip_address

        packet[28:34] = self.mac
        packet[34:44] = b'\x00' * 10
        
        packet[44:236]= b'\x00' * 192
        packet[236:240] =  b'\x63\x82\x53\x63' #Magic Cookie
        packet[240:243] =  b'\x35\x01\x02' # Message Type(code=53 len=1 type=2(DHCPDISCOVER))
        packet[243:245] = b'\x01\x04' #subnet mask
        packet[245:249] = inet_aton(self.subnetMask) 
        packet[249:251] = b'\x03\x04' #router
        packet[251:255] = inet_aton(self.router) #router
        packet[255:257] = b'\x33\x04' #lease time
        packet[257:261] = convertBytes(self.leaseTime,4)
        packet[261:263]= b'\x36\x04' #DHCP server
        packet[263:267]= inet_aton(self.DHCPServer)
        packet[267:269]= b'\x07\x04' #DNS servers
        packet[269:273]= inet_aton(self.DNS1)
        packet[273:275]= b'\x07\x04' #DNS servers
        packet[275:279]= inet_aton(self.DNS2)
        packet[279:281]= b'\x07\x04' #DNS servers
        packet[281:285]= inet_aton(self.DNS3)
        
        packet += b'\xff'
        return bytes(packet)
class DHCPRequest:
    def __init__(self,xid,data):
        self.data = data
        self.xid = xid
        self.unPack()
    def unPack(self):
        print("------------DHCPRequest-------------")
        if self.data[4:8] == self.xid:
            print("Offer IP request: " + '.'.join(map(lambda x:str(x), data[248:252])))
            print("DHCP server: " + '.'.join(map(lambda x:str(x), data[254:258])))
class DHCPACK:

    def __init__(self,xid,mac,OfferIP,nextServerIP,subnetMask,router,leaseTime,DHCPServer,DNS1,DNS2,DNS3):
        self.xid = xid
        self.mac = mac
        self.OfferIP =OfferIP
        self.nextServerIP = nextServerIP
        self.subnetMask = subnetMask
        self.router = router
        self.leaseTime = leaseTime
        self.DHCPServer = DHCPServer
        self.DNS1 = DNS1
        self.DNS2 = DNS2
        self.DNS3 = DNS3
    def protocolPacket(self):
        
        packet = bytearray(246)
        packet[0] = 2 #self.message_type
        packet[1] = 1 #self.hardware_type
        packet[2] = 6 #self.hardware_address_length
        packet[3] = 0 #self.hops

        packet[4:8] = self.xid #xid
        packet[ 8:10] = b'\x00\x00' #SECS
        packet[10:12] = b'\x00\x00' #FLAGS

        packet[12:16] = inet_aton('0.0.0.0') #client_ip_address
        packet[16:20] = inet_aton(self.OfferIP) #your_ip_address
        packet[20:24] = inet_aton(self.nextServerIP) #next_server_ip_address
        packet[24:28] = inet_aton('0.0.0.0') #relay_agent_ip_address

        packet[28:34] = self.mac
        packet[34:44] = b'\x00' * 10
        
        packet[44:236]= b'\x00' * 192
        packet[236:240] =  b'\x63\x82\x53\x63' #Magic Cookie
        packet[240:243] =  b'\x35\x01\x05' # Message Type(code=53 len=1 type=2(DHCPDISCOVER))
        packet[243:245] = b'\x01\x04' #subnet mask
        packet[245:249] = inet_aton(self.subnetMask) 
        packet[249:251] = b'\x03\x04' #router
        packet[251:255] = inet_aton(self.router) #router
        packet[255:257] = b'\x33\x04' #lease time
        packet[257:261] = convertBytes(self.leaseTime,4)
        packet[261:263]= b'\x36\x04' #DHCP server
        packet[263:267]= inet_aton(self.DHCPServer)
        packet[267:269]= b'\x06\x04' #DNS servers
        packet[269:273]= inet_aton(self.DNS1)
        packet[273:275]= b'\x06\x04' #DNS servers
        packet[275:279]= inet_aton(self.DNS2)
        packet[279:281]= b'\x06\x04' #DNS servers
        packet[281:285]= inet_aton(self.DNS3)
        
        packet += b'\xff'

        return bytes(packet)
if __name__ == '__main__':
    OfferIP = '192.168.1.100'
    nextServerIP = '192.168.1.1'
    subnetMask = '255.255.255.0'
    router = '192.168.1.1'
    leaseTime = 86400
    DHCPServer = '192.168.1.1'
    DNS1 = '9.7.10.15'
    DNS2 = '9.7.10.16'
    DNS3 = '9.7.10.18'
    dhcps = socket(AF_INET, SOCK_DGRAM) 
    dhcps.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    try:
        dhcps.bind(('', 67))    
    except Exception as e:
        print(e)
        print('por 67 in use')
        dhcps.close()
        exit()
    dhcps.settimeout(20)
    
    try:
        while True:
            data = dhcps.recv(1024)
            discoverPacket = DHCPDiscover(data)
            offerPacket = DHCPOffer(discoverPacket.xid,discoverPacket.mac,OfferIP,nextServerIP,subnetMask,router,leaseTime,DHCPServer,DNS1,DNS2,DNS3)
            dhcps.sendto(offerPacket.protocolPacket(), ('<broadcast>', 68))
            data = dhcps.recv(1024)
            requestPacket = DHCPRequest(discoverPacket.xid,data)
            ackPacket = DHCPACK(discoverPacket.xid,discoverPacket.mac,OfferIP,nextServerIP,subnetMask,router,leaseTime,DHCPServer,DNS1,DNS2,DNS3)
            dhcps.sendto(ackPacket.protocolPacket(), ('<broadcast>', 68))
    except timeout as e:
        print(e)
    except KeyboardInterrupt as e:
        print(e)
    dhcps.close()

