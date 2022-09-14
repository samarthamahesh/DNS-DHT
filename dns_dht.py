import sys
import socket
import _thread

from yaml import parse
from kad_dht import DHT
from datetime import datetime
import argparse


def set_dhts(num_nodes):
    dht_nodes = []

    for i in range(num_nodes):
        dht_nodes.append(DHT('127.0.0.1', 3000+i, seeds=[('127.0.0.1', 3000+j) for j in range(i)]))

    return dht_nodes


class DNSQuery:

    def __init__(self, data):
        self.data = data
        self.domain = ''

        tipo = (data[2] >> 3) & 15
        if tipo == 0:
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += data[ini+1:ini+lon+1].decode('ascii')+'.'
                ini += lon+1
                lon = data[ini]

            self.domain = self.domain[:-1]
    
    
    def getquestiondomain(self, data):
        state = 0
        expectedlength = 0
        domainstring = ''
        domainparts = []
        x = 0
        y = 0
        for byte in data:
            if state == 1:
                if byte != 0:
                    domainstring += chr(byte)
                x += 1
                if x == expectedlength:
                    domainparts.append(domainstring)
                    domainstring = ''
                    state = 0
                    x = 0
                if byte == 0:
                    domainparts.append(domainstring)
                    break
            else:
                state = 1
                expectedlength = byte
            y += 1

        questiontype = data[y:y+2]

        return (domainparts, questiontype)


    def get_flags(self, flags):
        byte1 = bytes(flags[:1])
        byte2 = bytes(flags[1:2])

        rflags = ''

        QR = '1'
        
        OPCODE = ''
        for bit in range(1,5):
            OPCODE += str(ord(byte1)&(1<<bit))

        AA = '1'
        TC = '0'
        RD = '0'

        RA = '0'
        Z = '000'
        RCODE = '0000'
        
        return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

    def respuesta(self, ips):
        # DNS Header

        TransactionID = self.data[:2]
        Flags = self.get_flags(self.data[2:4])

        QDCOUNT = b'\x00\x01'
        ANCOUNT = len(ips).to_bytes(2, byteorder='big')
        NSCOUNT = (0).to_bytes(2, byteorder='big')
        ARCOUNT = (0).to_bytes(2, byteorder='big')

        dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
        

        # Build DNS question

        domain, questiontype = self.getquestiondomain(self.data[12:])
        rectype = 'a'
        recttl = '400'

        dnsquestion = b''

        for part in domain:
            length = len(part)
            dnsquestion += bytes([length])

            for char in part:
                dnsquestion += ord(char).to_bytes(1, byteorder='big')

        if rectype == 'a':
            dnsquestion += (1).to_bytes(2, byteorder='big')

        dnsquestion += (1).to_bytes(2, byteorder='big')


        # Build DNS answer

        dnsbody = b''

        for ip in ips:
            rbytes = b'\xc0\x0c'

            rbytes += bytes([0]) + bytes([1])
            rbytes += bytes([0]) + bytes([1])

            rbytes += int(recttl).to_bytes(4, byteorder='big')

            rbytes = rbytes + bytes([0]) + bytes([4])

            for part in ip.split('.'):
                rbytes += bytes([int(part)])

            dnsbody += rbytes

        # Return Response

        return dnsheader + dnsquestion + dnsbody

def get_ip_by_domain(domain, dht_node):
    return dht_node[domain]

def query_send_ip(data, addr, udps, dht_node, reqtime):
    try:
        p = DNSQuery(data)
        print('%s Request domain: %s from %s' % (reqtime.strftime("%H:%M:%S.%f"), p.domain, addr[0]))
        ip = get_ip_by_domain(p.domain, dht_node)
        udps.sendto(p.respuesta(ip), addr)
        dis = datetime.now() - reqtime
        print('%s Request from %s cost %s : %s -> %s' % (reqtime.strftime("%H:%M:%S.%f"), addr[0], dis.seconds + dis.microseconds/1000000, p.domain, get_ip_by_domain(p.domain, dht_node)))
    
    except Exception as e:
        print('query for:%s error:%s' % (p.domain, e))


def host_ip_map(hosts_file, node):
    try:
        with open(hosts_file, 'r') as f:
            lines = f.read().split('\n')[1:-1]

            for line in lines:
                host, _, ip = line.split(',')
                ips = ip.split()
                
                node[host] = ips

            f.close()
    except:
        Exception("Error in database!!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--num_nodes',
                        type=int,
                        required=True)

    parser.add_argument('--data_path',
                        type=str,
                        required=True)

    args = parser.parse_args()
    num_nodes = args.num_nodes
    data_path = args.data_path

    # Setup DHT nodes
    dht_nodes = set_dhts(num_nodes)
    print("DHT nodes are set up!")

    host_ip_map(data_path, dht_nodes[0])
    print("DNS lookup table is ready!!")

    try:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(('127.0.0.1', 53))

    except Exception as e:
        print("Failed to create socket on UDP port 53:", e)
        sys.exit(1)

    print("Listening for queries!!!")
    try:
        while 1:
            data, addr = udps.recvfrom(1024)
            _thread.start_new_thread(query_send_ip, (data, addr, udps, dht_nodes[0], datetime.now()))
    
    except KeyboardInterrupt:
        print("\nExit!")

    except Exception as e:
        print("\nError: %s" % e)
    
    finally:
        udps.close()