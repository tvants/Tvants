#!/usr/bin/env python
import asyncore, socket, psyco, binascii, struct, time, threading, sys, collections, hashlib, random, optparse #, math
import asfd, UI7
eurosoccer = 'tvants://list.tvants.com/tvants/?k=7aac15fdc859f76e9425d0e3150a5998'
cctv5 = 'tvants://list.tvants.com/tvants/?k=903d0c7dcab9d2718efce2b40509b8b3'
class tvants(asyncore.dispatcher):
	def __init__(self, dst, bindport):
		self.dst = dst
		self.bindport = bindport
		self.recvbuf = ''
		self.sendbuf = ''
		self.typecode = None
		self.msglen = None
		asyncore.dispatcher.__init__(self)
	def cn(self):
		try:
			self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
			self.set_reuse_addr()
			self.bind( ('', self.bindport) )
		except socket.error, errmsg:
			#~ print 'Error creating socket!', errmsg
			self.handle_close()
			return False
		try:
			self.connect(self.dst)
		except socket.error, errmsg:
			if errmsg[0] == 99:
				pass # EADDRNOTAVAIL
			else:
				#~ print 'sock error connecting', errmsg, dst
				pass
			self.handle_close()
	def handle_write(self):
		try:
			sent = self.send(self.sendbuf)
			self.sendbuf = self.sendbuf[sent:]
			#~ print 'Sent'
		except socket.error, errmsg:
			#~ print 'Error trying send!', errmsg, self.dst
			self.handle_close()
	def handle_read(self):
		try:
			data = self.recv(8192)
		except socket.error, errmsg:
			if errmsg[0] == 110:
				pass # Connection timeout
			elif errmsg[0] == 111:
				pass # Connection refused
			else:
				#~ print 'Error trying recv!', errmsg, self.dst
				pass
			self.handle_close()
			return False
		self.recvbuf += data
		self.proc_recv()
	def proc_recv(self):
		if not self.typecode:
			try:
				self.msglen = struct.unpack_from('<L', self.recvbuf, 4)[0]
				self.typecode = struct.unpack_from('!B', self.recvbuf, 12)[0]
			except struct.error:
				if len(self.recvbuf) == 0:
					#~ print 'Struct error! Received 0 byte from', self.dst
					pass
				return
		if len(self.recvbuf) >= self.msglen:
			self.proc_msg.get(self.typecode, self.dummy)(self.recvbuf[:self.msglen])
			self.recvbuf = self.recvbuf[self.msglen:]
			self.typecode= None
			if len(self.recvbuf) > 0:
				self.proc_recv()
	def public_ip(self, int_ip):
		if (int_ip >= 0x0a000000) and (int_ip <= 0x0affffff):
			return False
		if (int_ip >= 0xa9000000) and (int_ip <= 0xa9ffffff):
			return False
		if (int_ip >= 0xac000000) and (int_ip <= 0xacffffff):
			return False
		if (int_ip >= 0xc0a80000) and (int_ip <= 0xc0a8ffff):
			return False
		if (int_ip >= 0x00000000) and (int_ip <= 0x01ffffff):
			return False
		return True
	def encodeDB(self, string): return string.encode('utf-16').encode('hex')[4:]
	def parse_field(self, data, offset):
		(type, lenx) = struct.unpack_from('<HH', data, offset)
		try:
			bytesize = self.len_codes[type][(lenx - self.len_codes[type][0])]
			fmt = { 1:'B', 2:'H', 3:'HB', 4:'L' }[bytesize]
		except (KeyError, IndexError):
			#~ print 'Type:', type, offset
			#~ print binascii.hexlify(data)
			raise
		fielddata = struct.unpack_from('<' + fmt, data, offset + 4)
		return type, fielddata, offset + 4 + bytesize, bytesize
	def rev_endian(self, intdata, bytesize):
		fmt = { 1:'B', 2:'H',  4:'L' }[bytesize]
		return struct.unpack('!' + fmt, struct.pack('<' + fmt, intdata))[0]
	def hexlify(self, intdata, bytesize):
		hexfmt =  '%.' + str(bytesize * 2) +'x'
		return hexfmt % intdata
	def getlen(self, intdata, bytesize):
		reversed = self.rev_endian(intdata, bytesize)
		return self.hexlify(reversed, bytesize)
	def readable(self): return True
	def writable(self):
		try: return (len(self.sendbuf) > 0)
		except AttributeError: return False
	def handle_connect(self): pass #~ print 'Handle connect', self.connected, self.closing
	def handle_expt(self):
		#~ open('/dev/dsp','w').write(''.join(chr(128 * (1 + math.sin(math.pi * 440 * i / 100.0))) for i in xrange(1000)))
		if not self.connected:
			#~ print '\nExpt: not connected'
			pass
		else:
			#~ print 'Handle expt', self.dst
			self.handle_close()
class tracker(tvants):
	def __init__(self, dst, bindport, chn_uri):
		self.proc_msg = { 0x02: self.connect_reply, 0x08: self.chn_reg_reply, 0x0a: self.peerlist_reply, 0x88: self.chnlist_reply, 0x68: self.chnlist_reply }
		self.peers = []
		self.chnlist = []
		self.chn_uri = chn_uri
		self.status = 'closed'
		tvants.__init__(self, dst, bindport)
	def connect_reply(self, data):
		status = struct.unpack_from('!B', data, 17)[0]
		if status != 0x00: # or 0x05 
			#~ print 'Tracker Connect rejected, Code: %#.2x' % status
			self.handle_close()
		else:
			#~ print 'Tracker Connect accepted', len(data)
			#~ host_type = struct.unpack_from('!H', data, 29)[0] # 0x0146 for tracker
			self.status = 'connected'
			if self.chn_uri:
				self.channel_register()
			elif len(self.chnlist) == 0:
				self.chnlist_req()
	def chn_reg_reply(self, data):
		#~ print 'Channel reg reply', len(data)
		self.status = 'registered'
		self.peerlist_request()
	def peerlist_reply(self, data):
		self.parse_peerlist(data)
		#~ print 'Peers: %d' % len(self.peers)
	def parse_peerlist(self, data):
		del self.peers[:]
		offset = 39
		self.len_codes = { 0x0004:(1, 4, 4, 4, 4), 0x0041:(17, 2, 4), 0x0042:(16, 1, 2), 0x0043:(17, 2, 4), 0x0044:(16, 1, 2), 0x0045:(16, 1, 2) }
		# 0x0045 - id, 0x0044 - port, 0x0043 - ip, 0x0042 - port, 0x0041 - ip
		peerdata = {}
		listsize = struct.unpack_from('<L', data, (offset - 4))[0]
		while offset < listsize:
			(type, fielddata, offset, bytesize) = self.parse_field(data, offset)
			peerdata[type] = fielddata[0]
			if type == 0x0045:
				datatypes = peerdata.keys()
				if 0x0043 in datatypes:
					rev_ip = peerdata[0x0043]
				else:
					rev_ip = peerdata[0x0041] # private ip ?
				ip = self.rev_endian(rev_ip, 4)
				if 0x0044 in datatypes:
					port = peerdata[0x0044]
				elif 0x0042 in datatypes:
					port = peerdata[0x0042]
				else: port = 16800
				id = peerdata[0x0045]
				if self.public_ip(ip):
					self.peers.append((ip, port, id))
					#~ print 'Peer: %.8x Port: %d ID: %#.2x' % (ip, port, id)
				peerdata.clear()
		if self.peers:
			queen.peerlist_evt.set()
	def connects(self, ipstring):
		self.status = 'connecting'
		self.cn()
		p1 = '04000c00'
		p3 = '5456414e545320545241434b000800060000004f004b00000043001100015056001100015356001100014941000800'
		p5 = self.encodeDB(ipstring)
		p4 = self.getlen((len(p5) // 2) + 2, 4)
		p6 = '00004950001200a1414348001100014f54001100014f560013000501280a4f4c001200090446560008001200000031002e0030002e0030002e00350039000000524e0012004303'
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6) // 2) + 4, 4)
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 +p4 +p5 +p6)
	def chnlist_req(self):
		p = '040005002900000043001100054b000800020000000000435600110002534b001100004d5200110064'
		self.sendbuf = binascii.unhexlify(p)
	def chnlist_reply(self, data):
		self.len_codes = { 0x0041:(16, 1, 2), 0x0052:(16, 1), 0x004e:(7, 4) }
		offset = data.find(struct.pack('!H', 0x000000), 16) + 3
		tvant_url = data[16:offset].decode('utf_16')[:-1]
		chndata = {}
		while True:
			(type, chndata[type], offset, bytesize) = self.parse_field(data, offset)
			if type == 0x004e:
				num_peers = chndata[0x0041][0]
				chn_namelen = chndata[0x004e][0]
				chn_name = data[offset:(offset +chn_namelen)]
				break
		try:
			chn_name =  binascii.hexlify(chn_name).decode('hex').decode('utf-16')[:-1].encode('utf-8')
		except:
			chn_name = binascii.hexlify(chn_name)
		self.chnlist.append((chn_name, tvant_url, num_peers))
	def channel_register(self):
		p1 = '04000200'
		p3 = '4300110007504c000800'
		p5 = self.encodeDB(self.chn_uri)
		p4 = self.getlen((len(p5) // 2) + 2, 4)
		p6 = '0000'
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6) // 2) + 4, 4)
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 +p4 +p5 + p6)
	def peerlist_request(self):
		p1 = '04000400'
		p3 = '4300110009504c000800'
		p5 = self.encodeDB(self.chn_uri)
		p4 = self.getlen((len(p5) // 2) + 2, 4)
		p6 = '0000504b000800020000000000435600110001'
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6) // 2) + 4, 4)
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 +p4 +p5 +p6)
	def handle_close(self):
		self.status = 'closed'
		self.close()
	def dummy(self, data):
		pass
		#~ print 'Tracker Dummy %#.2x Data length: %d' % (self.typecode, len(data))
class ant(tvants):
	def __init__(self, dst, bindport, channel, peerkey):
		self.proc_msg = { 0x02: self.connect_reply, 0x13: self.auth_reply, 0x0c: self.asfheader_reply, 0x11: self.buffermap_reply,
			0x14: self.chunk_reply, 0x15: self.chunk_complete, 0x08: self.unknown08, 0x0f: self.bm_request_ack }
		self.len_codes = { 0x0023:(17, 2, 4), 0x0031:(16, 1, 2, 4), 0x0043:(16, 1), 0x0044:(8207, 4), 0x0048:(8207, 4), 0x004c:(16, 2), 
			0x004d:(8207, 4), 0x004e:(16, 1), 0x004f:(16, 2, 3), 0x0052:(16, 1), 0x0053:(16, 1) }
		self.bufferhead = None
		self.buffermap = set([])
		self.mapsize = 0
		self.addr_size = None
		self.lastrecv = None
		self.numframes = 0
		self.numchunks = 0
		self.requests = 0
		self.chunk = {}
		self.unknowns = 0
		tvants.__init__(self, dst, bindport)
		self.connects(channel, peerkey)
	def connect_reply(self, data):
		offset = 13
		while True:
			(type, fielddata, offset, bytesize) = self.parse_field(data, offset)
			if type == 0x0052:
				status = fielddata[0]
				if status == 0x00: 
					self.auth()
				else: # 0x05 or 0x10
					#~ print 'Peer Connect rejected, Code: %#.2x' % status
					self.handle_close()
				break
		#~ host_type = struct.unpack_from('!H', data, 29)[0] # 0x0152 for p2p
	def connects(self, channel, peerkey):
		self.cn()
		p1 = '04000700'
		p3 = '5456414e5453205348415245000800060000004f004b0000004300110001505600110001535600110001524e001200430341000800'
		p5 = self.encodeDB(channel)
		p4 = self.getlen((len(p5) // 2) + 2, 4)
		p6 = '00004348001100'
		fmt = ['!B', '<H'][(peerkey > 255)]
		p7 = binascii.hexlify(struct.pack(fmt, peerkey))
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6 + p7) // 2) + 4, 4)
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 +p4 +p5 + p6 + p7)
	def auth(self):
		p1 = '04000200'
		p3 = '4300110012'
		p4 = '44001020'
		p6 = 'a657b91e7f19c6407d3861cc08485d94be4066e4c67ef2ae600b75e4c021d426'
		p5 = self.getlen((len(p6) // 2), 4)
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6) // 2) + 4, 4)
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 +p4 +p5 + p6)
	def auth_reply(self, data):
		queen.neighbours[self.dst] = self
		self.asfheader()
	def asfheader(self):
		if len(asfsrv.asfheader) < 2:
			asf = '0400030018000000430011000b5300110000414c00110000'
		else:
			asf = '0400030018000000430011000b5300110001414c00110004'
		self.sendbuf = binascii.unhexlify(asf)
	def asfheader_reply(self, data):
		if len(asfsrv.asfheader) < 2:
			offset = 13
			while True:
				(type, fielddata, offset, bytesize) = self.parse_field(data, offset)
				if type == 0x0048:
					headerlen = fielddata[0]
					asfsrv.addheader(data[offset:(offset + headerlen)])
					break
		self.buffermap_request()
	def buffermap_request(self):
		p = '040001000d000000430011000e'
		self.sendbuf = binascii.unhexlify(p)
	def buffermap_reply(self, data):
		self.parse_map(data)
		if len(self.sendbuf) == 0:
			chunk_ids = queen.fetchlist.intersection(self.buffermap).difference(set(queen.holdq))
			if len(chunk_ids):
				chunk_id = min(chunk_ids)
				self.chunk_request(chunk_id, self.addr_size)
	def parse_map(self, data):
		self.buffermap.clear()
		mapdata = {}
		offset = 8
		while True:
			(type, mapdata[type], offset, bytesize) = self.parse_field(data, offset)
			if type == 0x0031:
				self.bufferhead = mapdata[0x0031][0]
				self.addr_size = bytesize
			if type == 0x004d:
				self.mapsize = mapdata[0x004d][0]
				mapdata.clear()
				#~ fourc = mapdata[0x004c][0] #~ foure = mapdata[0x004e][0] #~ fourf = mapdata[0x004f]
				#~ tail = binascii.hexlify(data[offset:]) #~ print binascii.hexlify(data[offset:(offset + fielddata[0])]), binascii.hexlify(data)
				for bytepos in xrange(0, self.mapsize):
					byte = struct.unpack_from('B', data, offset + bytepos)[0]
					mask = 0x80
					for bitpos in range(8):
						if byte & mask == mask:
							self.buffermap.add(self.bufferhead + (bytepos * 8) + bitpos)
						mask = mask >> 1
				#~ if len(queen.fetchlist) == 0:
					#~ start = self.bufferhead + (self.mapsize * 8 * 48 // 100)
					#~ queen.addfetch(start, 8888)
				fetchlistlen = len(queen.fetchlist)
				if fetchlistlen == 0:
					start = self.bufferhead + (self.mapsize * 8 * 48 // 100)
					queen.addfetch(start, 1388)
				elif fetchlistlen < 888:
					queen.addfetch(max(queen.fetchlist), 888)
				if len(self.buffermap) < 6:
					self.handle_close()
				break
		#~ print 'Map', self.dst[0], len(data), 'Head: %#.8x Mapsize: %d' % (self.bufferhead, mapsize), #~ print '4e: %#.2x' % foure, fourf, tail
	def chunk_request(self, chunk_id, bytesize):
		p1 = '04000200'
		p3 = '430011000542'
		p4 = '2300'
		p5 = self.getlen({ 2:18, 4:19 }[bytesize], 2)
		p6 = self.getlen(chunk_id, bytesize)
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6) // 2) + 4, 4)
		if len(queen.holdq) > (len(queen.neighbours) + 8):
			queen.holdq.popleft()
		queen.holdq.append(chunk_id)
		self.requests += 1
		(quotient, remainder) = divmod(self.requests, 8)
		if quotient > 0 and (remainder == 0):
			if (self.numchunks / float(self.requests)) < (1 / 8.0):
				self.handle_close()
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 + p4 + p5 + p6)
	def chunk_reply(self, data):
		offset = 14
		while True:
			(type, fielddata, offset, bytesize) = self.parse_field(data, offset)
			if type == 0x0023:
				chunk_id = fielddata[0]
				self.numframes += 1
				self.parse_frame(data, bytesize, chunk_id)
				break
	def chunk_ack(self, chunk_id, bytesize):
		p1 = '04000200'
		p3 = '430011000942'
		p4 = '2300'
		p5 = self.getlen({ 2:18, 4:19 }[bytesize], 2) # chunk_id byte size
		p6 = self.getlen(chunk_id, bytesize) # chunk_id
		p2 = self.getlen((len(p1 + p3 + p4 + p5 + p6) // 2) + 4, 4)
		self.sendbuf = binascii.unhexlify(p1 + p2 + p3 + p4 + p5 + p6)
	def chunk_complete(self, data):
		offset = 14
		while True:
			(type, fielddata, offset, bytesize) = self.parse_field(data, offset)
			if type == 0x0023:
				self.lastrecv = fielddata[0]
				#~ if self.lastrecv in self.chunk.keys():
				asfsrv.addchunk(self.chunk[self.lastrecv], self.lastrecv)
				self.numchunks += 1
				queen.fetchlist.discard(self.lastrecv)
				self.chunk_ack(self.lastrecv, bytesize)
				#~ print 'Chunk', self.lastrecv, 'complete!', self.numframes, len(tk.fetchlist), len(self.chunk[self.lastrecv]), len(tk.neighbours)
				self.chunk.clear()
				break
	def parse_frame(self, data, addr_size, chunk_id):
		offset = 14
		while True:
			(type, fielddata, offset, bytesize) = self.parse_field(data, offset)
			if type == 0x0044:
				#~ framenum = struct.unpack_from('<L', data, offset)[0]
				framelen = struct.unpack_from('<L', data, offset + 4)[0]
				offset += 8
				if framelen == asfsrv.pktsizes[0]:
					#~ x = binascii.hexlify(data[offset + 3])
					#~ if x == 0x09:
						#~ break
					#~ x = binascii.hexlify(data[offset:(offset + 38)])
					#~ v82.write(str(framelen) + ' ')
					#~ v82.write(x)
					#~ v82.write('\n')
					try:
						self.chunk[chunk_id].append(data[offset:])
					except KeyError:
						self.chunk[chunk_id] = [data[offset:]]
				else:
					repacket = asfsrv.pkt_recode(data[offset:], framelen)
					#~ x = binascii.hexlify(data[offset:(offset + 38)])
					#~ v82.write(str(framelen) + ' ')
					#~ v82.write(x)
					#~ v82.write('\n')
					
					#~ v82.write(str(len(repacket)) + ' ')
					#~ v82.write(binascii.hexlify(repacket[:38]))
					#~ v82.write('\n')
					#~ print binascii.hexlify(data[offset:(offset + 38)]), framelen
					#~ print binascii.hexlify(repacket[:38]), len(repacket)
					
					try:
						self.chunk[chunk_id].append(repacket)
					except KeyError:
						self.chunk[chunk_id] = [repacket]
				break
	def bm_request_ack(self, data): pass
	def unknown08(self, data):
		#~ print 'Unknown', len(data), binascii.hexlify(data), self.dst[0]
		self.unknowns += 1
		if self.unknowns > 18:
			#~ print 'Too many unknowns from', self.dst[0], 'Received:', self.numframes
			self.handle_close()
	def dummy(self, data):
		pass
		#~ print 'Dummy %#.2x Data length: %d' % (self.typecode, len(data))
	def handle_close(self): 
		self.close()
		if self.dst in queen.neighbours:
			del queen.neighbours[self.dst]
			#~ print 'Removed', self.dst[0], 'Map:', len(self.buffermap), 'Req:', self.requests, self.numframes
class queen_ant():
	def __init__(self, trackerport, peerport, chn_uri):
		self.min_neighbours = 18
		self.trackerport = trackerport
		self.peerport = peerport
		self.chn_uri = chn_uri
		self.running = True
		
		self.neighbours = {}
		self.fetchlist = set([])
		self.holdq = collections.deque()
		self.net_evt = threading.Event()
		self.peerlist_evt = threading.Event()
		
		self.tracker = tracker(('list.tvants.com', 16600), self.trackerport, self.chn_uri)
		self.interface = UI7.ui_main(asfsrv, self)
		self.interface.initpanes()
		#~ self.interface.draw_all()
	def track(self):
		while self.running:
			if self.tracker.status == 'registered':
				self.tracker.peerlist_request()
			elif self.chn_uri or (len(self.tracker.chnlist) == 0):
				if self.tracker.status == 'closed':
					self.tracker.chn_uri = self.chn_uri
					self.tracker.connects('207.46.19.190')
				elif self.chn_uri:
					self.tracker.channel_register()
				elif len(self.tracker.chnlist) == 0:
					self.tracker.chnlist_req()
			if asyncore.socket_map:
				self.net_evt.set()
			else:
				self.net_evt.clear()
			num_nb = len(self.neighbours)
			if num_nb >= self.min_neighbours:
				waittime = 33 + num_nb - self.min_neighbours
			else:
				waittime = 9
			for x in xrange(waittime):
				time.sleep(1.0)
				if self.interface.quit:
					return 0
				#~ if self.tracker.status == 'closed' or (self.tracker.status == 'connecting'):
				if self.tracker.status == 'closed':
					break
	def ui(self):
		while self.running:
			self.interface.run()
			if self.interface.quit:
				self.running = False
	def ants(self):
		while self.running:
			self.peerlist_evt.wait()
			num_nb = len(self.neighbours)
			if num_nb < self.min_neighbours:
				random.shuffle(self.tracker.peers)
				y = 0
				for peer in self.tracker.peers:
					ip = self.IntToDottedIP(peer[0])
					if (ip, peer[1]) not in self.neighbours.keys():
						ant((ip, peer[1]), self.peerport, self.chn_uri, peer[2])
						y += 1
						if y > (self.min_neighbours - num_nb + 8):
							break
				#~ self.net_evt.set()
			self.peerlist_evt.clear()
	def asyncore_loop(self):
		while self.running:
			self.net_evt.wait()
			#~ asyncore.loop(timeout=1.0)
			asyncore.loop(timeout=1.0, count=len(asyncore.socket_map))
	def addfetch(self, chunk_id, size):
		for x in xrange(size):
			self.fetchlist.add(chunk_id + x)
	def IntToDottedIP(self, intip):
		octet = ''
		for exp in [3,2,1,0]:
			octet = octet + str(intip / ( 256 ** exp )) + "."
			intip = intip % ( 256 ** exp )
		return(octet.rstrip('.'))
if __name__ == "__main__":
	parser = optparse.OptionParser()
	parser.add_option('-v', '--videoport', type='int', dest='videoport', default=1688)
	parser.add_option('-p', '--peerport', type='int', dest='peerport', default=16800)
	parser.add_option('-t', '--trackerport', type='int', dest='trackerport', default=13800)
	parser.add_option('-u', '--uri', dest='uri', default='')
	(options, args) = parser.parse_args()

	asfsrv = asfd.asfServer(('localhost', options.videoport), asfd.asfHandler)
	threaded_asfsrv = threading.Thread(target=asfsrv.serve_forever)
	threaded_asfsrv.start()
	queen = queen_ant(options.trackerport, options.peerport, options.uri)
	tracker_thread = threading.Thread(target=queen.track)
	tracker_thread.start()
	ants_thread = threading.Thread(target=queen.ants)
	ants_thread.start()
	ui_thread = threading.Timer(0.8, queen.ui)
	ui_thread.start()
	aloop = threading.Thread(target=queen.asyncore_loop)
	aloop.start()
	
	#~ v82 = open('v82.txt','w')
	tracker_thread.join()
	#~ v82.close()
	sys.exit(0)