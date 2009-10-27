import SocketServer, threading, binascii, struct, socket, re

class asfHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		self.data = self.request.recv(1024).strip()
		if len(self.server.asfheader) < 2 or (len(self.server.chunks) < 1):
			self.request.close()
			return
		self.request.send(self.server.asfheader[0])
		self.request.send(self.server.asfheader[1])
		
		startpos = re.findall(r'^GET\s*\/([0-9]*)\s*HTTP', self.data, re.M + re.I)[0]
		chunk_ids = self.server.chunks.keys()
		chunk_id = sorted(chunk_ids)[int(startpos)]
		cskipped = 0
		s = 0
		while True:
			if chunk_id in self.server.chunks.keys():
				cskipped = 0
				self.server.playing = chunk_id
				for frame in self.server.chunks[chunk_id]:
					try:
						self.request.send(frame)
					except socket.error, errmsg:
						if errmsg[0] == 104:
							self.server.playing = '-'
							self.server.skipped = 0
							return True
			else:
				#~ print 'Skipping', s
				self.server.skipped += 1
				cskipped += 1
			chunk_id += 1
			s += 1
			if cskipped > 18:
				self.request.close()
				self.server.skipped = 0
				self.server.playing = '-'
				return
class asfServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	allow_reuse_address = True
	def __init__(self, server_address, RequestHandlerClass):
		SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
		self.bindport = server_address[1]
		self.asfheader = []
		self.skipped = 0
		self.asfheader.append(binascii.unhexlify('485454502f312e3120323030204f4b0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6f637465742d73747265616d0d0a5365727665723a20436f7567617220342e312e302e333835370d0a43616368652d436f6e74726f6c3a206e6f2d63616368650d0a507261676d613a206e6f2d63616368650d0a507261676d613a20636c69656e742d69643d323136363030390d0a507261676d613a2066656174757265733d2262726f616463617374220d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a'))
		self.chunks = {}
		self.pktsizes = ()
		self.playing = '-'
	def addheader(self, hdr):
		file_header_pos = hdr.find(binascii.unhexlify('a1dcab8c47a9cf118ee400c00c205365'))
		self.pktsizes = struct.unpack_from('<LLL', hdr, (file_header_pos + 92))
		if self.pktsizes[0] == self.pktsizes[1]:
			#~ print 'Asf header reply', len(hdr), 'Packet Size:', self.pktsizes[0], 'Max Bitrate:', self.pktsizes[2] // 1024, 'kbps'
			self.asfheader.append(hdr)
		else:
			print 'Invalid ASF header'
	def addchunk(self, chunk, chunk_id):
		self.chunks[chunk_id] = chunk
		if len(self.chunks) > 238:
			videohead = min(self.chunks.keys())
			try:
				del self.chunks[videohead]
			except KeyError:
				pass
	def pkt_recode(self, packet, framelen):
		packlen = packsize = padsize = 0
		v82, flags = struct.unpack_from('!BxxB', packet)
		if v82 == 0x82:
			packlen = (flags >> 5) & 3
			pad = (flags >> 3) & 3
			seg = (flags & 1)
			offset = 5
			if packlen:
				offset += 2
			if pad:
				offset += pad
			sendtime_duration = packet[offset:(offset + 6)]
			offset += 6
			if seg:
				smt = packet[offset]
				offset += 1
			p2 = packet[offset:]
			
			lendiff = self.pktsizes[0] - framelen
			#~ if (lendiff == 2 and flags == 0x40) or (lendiff == 1 and flags == 0x48):
			if (lendiff == 2 and flags == 0x40) or (lendiff == 1 and flags == 0x48) or (lendiff == 1 and flags == 0x09):
				padlen = 2
			else:
				padlen = (lendiff > 255) + 1
			#~ padlen = (lendiff > 255) + 1
			if pad:
				padsize = lendiff
				if (lendiff == 1 and flags == 0x48):
					padsize = 0
					flags = 0x50
				elif (lendiff == 1 and flags == 0x09):
					padsize = 0
					flags = 0x11
			else:
				padsize = lendiff - padlen
				flags = flags + {1:0x08, 2:0x10}[padlen]
			#~ print padsize
			p1 = packet[:3] + struct.pack('!B', flags) + packet[4]
			if packlen:
				p1 += struct.pack('<H', self.pktsizes[0])
			fmt = {1:'!B', 2:'<H'}[padlen ]
			p1 += struct.pack(fmt, padsize) + sendtime_duration
			if seg:
				p1 += smt
			return p1 + p2 + struct.pack((str(padsize) + 's'), chr(0))