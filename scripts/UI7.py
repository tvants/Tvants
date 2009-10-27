#!/usr/bin/env python
# -*- coding: utf-8 -*-
import curses, locale, sys, itertools
from operator import itemgetter, attrgetter
#~ curses.start_color()
#~ curses.cbreak()
#~ curses.raw()
class pane:
	def __init__(self, title, height, width, y, x):
		self.title = title
		self.pads = {}
		self.curline = 0
		self.height = height
		try:
			self.win = curses.newwin(self.height, width, y, x)
		except curses.error:
			print 'Can\'t create Pane window'
			sys.exit(-1)
		self.win.leaveok(1)
		self.win.keypad(1)
		self.win.box()
		if (self.title == 'Top Channels'):
			attr = curses.A_STANDOUT
		else:
			attr = curses.A_NORMAL
		self.chfocus(attr)
	def addpad(self, name, width):
		self.pads[name] = curses.newpad((self.height - 1), width)
	def fillpad(self, padname, values, width):
		for line, value in enumerate(values):
			if line == self.curline:
				self.pads[padname].addnstr(line+1, 1, value, width, curses.A_STANDOUT)
			else:
				self.pads[padname].addnstr(line+1, 1, value, width)
	def refreshpad(self, padname, y, x, width):
		self.pads[padname].noutrefresh(1,1, y,x, (y + self.height - 2), (x +width))
	def chfocus(self, attr):
		self.win.addstr(0, 2, self.title, attr)
		self.win.noutrefresh()
class ui_main:
	def __init__(self, asfsrv, queen):
		locale.setlocale(locale.LC_ALL, '')
		stdscr = curses.initscr()
		(self.scr_height, self.scr_width) = stdscr.getmaxyx()
		curses.halfdelay(10)
		curses.curs_set(0)
		curses.noecho()
		self.quit = False
		self.width1 = 30
		self.main_pane = pane('Main', 9, self.width1, 0,0)
		self.chn_pane = pane('Channel', 8, self.width1, 9,0)
		#~ self.chnlist_pane = pane('Top Channels', 19, self.width1, 17,0)
		self.chnlist_pane = pane('Top Channels', self.scr_height - 8 - 9, self.width1, 17,0)
		self.neighbours_pane = pane('Neighbours', self.scr_height, 43, 0,31)
		self.chn_pane_value_w = 15
		self.act_pane = self.chnlist_pane
		self.panes = self.gen_panes()
		self.asfsrv = asfsrv
		self.queen = queen
		self.neighbours = []
		self.chnlist = []
	def gen_panes(self):
		panes = [self.neighbours_pane, self.chnlist_pane]
		for pane in itertools.cycle(panes):
			yield pane
	def initpanes(self):
		self.main_pane.curline = -1
		self.main_pane.addpad('description', 15)
		self.main_pane.fillpad('description', ['peers:', 'neighbours:', 'min nb:', 'chunks:', 'tracker port:', 'peer port:',  'video port:'], 16)
		self.main_pane.refreshpad('description', 1,1, 13)
		self.main_pane.addpad('values', 13)
		self.chn_pane.addpad('description', 15)
		self.chn_pane.fillpad('description', ['Name:', 'Pkt size:', 'Max Bitrate:', 'Playing:', 'Skipped:', 'Fetchlist:'], 14)
		self.chn_pane.refreshpad('description', 10,1, 13)
		self.chn_pane.addpad('values', self.chn_pane_value_w)
		self.chnlist_pane.addpad('numpeers', 6)
		self.chnlist_pane.addpad('channel', 22)
		self.neighbours_pane.addpad('ip', 16)
		self.neighbours_pane.addpad('chunks', 6)
		self.neighbours_pane.addpad('requests', 5)
		self.neighbours_pane.addpad('map', 11)
	def draw_all(self):
		self.main_pane.pads['values'].clear()
		self.main_pane.fillpad('values', [ str(len(self.queen.tracker.peers)), str(len(self.queen.neighbours)), str(self.queen.min_neighbours), 
			str(len(self.asfsrv.chunks)), str(self.queen.tracker.bindport), str(self.queen.peerport), str(self.asfsrv.bindport) ], 10)
		self.main_pane.refreshpad('values', 1,15, 14)
		self.draw_chn()
		self.draw_chnlist()
		self.draw_nblist()
		curses.doupdate()
	def draw_chn(self):
		chn_name = '-'
		for chn in self.queen.tracker.chnlist:
			if self.queen.chn_uri == chn[1]:
				chn_name = chn[0]
				break
		self.chn_pane.pads['values'].clear()
		vlist = [ chn_name, '-', '-', str(self.asfsrv.playing), str(self.asfsrv.skipped), str(len(self.queen.fetchlist))]
		if len(self.asfsrv.pktsizes):
			vlist[1] = str(self.asfsrv.pktsizes[0])
			vlist[2] = str(self.asfsrv.pktsizes[2] // 1024) + ' kbps'
		self.chn_pane.fillpad('values', vlist, self.chn_pane_value_w)
		self.chn_pane.refreshpad('values', 10,15, self.chn_pane_value_w)
	def draw_chnlist(self):
		#~ self.chnlist = self.queen.tracker.chnlist[:17]
		self.chnlist = self.queen.tracker.chnlist[:(self.scr_height - 8 - 9 - 2)]
		num_peers = map(str, (map(itemgetter(2), self.chnlist)))
		chn_names = map(itemgetter(0), self.chnlist)
		self.chnlist_pane.pads['numpeers'].clear()
		self.chnlist_pane.fillpad('numpeers', num_peers, 5)
		self.chnlist_pane.refreshpad('numpeers', 18,1, 5)
		self.chnlist_pane.pads['channel'].clear()
		self.chnlist_pane.fillpad('channel', chn_names, 21)
		self.chnlist_pane.refreshpad('channel', 18,8, 21)
	def draw_nblist(self):
		self.neighbours_pane.pads['ip'].clear()
		self.neighbours_pane.pads['chunks'].clear()
		self.neighbours_pane.pads['requests'].clear()
		self.neighbours_pane.pads['map'].clear()
		
		nblist = list(self.queen.neighbours.iteritems())[:34]
		self.neighbours = map(itemgetter(0), nblist)
		if (self.neighbours_pane.curline + 1) > len(self.neighbours):
			self.neighbours_pane.curline = len(self.neighbours) - 1
		ips = map(itemgetter(0), self.neighbours)
		nb_info = map(itemgetter(1), nblist)
		numchunks = map(str, map(attrgetter('numchunks'), nb_info))
		#~ numframes = map(str, map(attrgetter('numframes'), nb_info))
		requests = map(str, map(attrgetter('requests'), nb_info))
		buffermaps = self.bm(nb_info)
		
		self.neighbours_pane.fillpad('ip', ips, 14)
		self.neighbours_pane.refreshpad('ip', 1,32, 16)
		self.neighbours_pane.fillpad('chunks', numchunks, 5)
		self.neighbours_pane.refreshpad('chunks', 1, 49, 6)
		self.neighbours_pane.fillpad('requests', requests, 4)
		self.neighbours_pane.refreshpad('requests', 1, 56, 5)
		self.neighbours_pane.fillpad('map', buffermaps, 18)
		self.neighbours_pane.refreshpad('map', 1, 62, 11)
	def bm(self, nb_info):
		mapsize = map(self.c_mapsize, map(attrgetter('mapsize'), nb_info))
		haves = map(self.c_bm, map(attrgetter('buffermap'), nb_info))
		return [ '/'.join((haves[x], m)) for x, m in enumerate(mapsize) ]
	def c_mapsize(self, arg):
		return str(arg * 8)
	def c_bm(self, arg):
		return str(len(arg))
	def run(self):
		keyaction = { curses.KEY_UP: self.up, curses.KEY_DOWN: self.down, ord('\t'):  self.toggle_active_pane, curses.KEY_DC: self.delete, 
			curses.KEY_F5:  self.refresh_chnlist,  ord('s'):  self.stop, ord('+'): self.increase, ord('-'): self.decrease, 
			ord('b'): self.buffermap_request, ord('c'): self.chchannel }
		input = self.act_pane.win.getch()
		if input == ord('q'):
			curses.endwin()
			self.quit = True
			return 0
		keyaction.get(input, curses.beep)()
		self.draw_all()
	def up(self):
		if self.act_pane.curline > 0:
			self.act_pane.curline -= 1
	def down(self):
		if self.act_pane == self.neighbours_pane:
			limit = len(self.neighbours)
		elif self.act_pane == self.chnlist_pane:
			limit = len(self.chnlist)
		if self.act_pane.curline == (limit - 1):
			self.act_pane.curline = 0
		else:
			self.act_pane.curline += 1
	def delete(self):
		if self.act_pane == self.neighbours_pane:
			try:
				nb = self.neighbours[self.neighbours_pane.curline]
				self.queen.neighbours[nb].handle_close()
			except KeyError:
				pass
	def toggle_active_pane(self):
		self.act_pane.chfocus(curses.A_NORMAL)
		self.act_pane = self.panes.next()
		self.act_pane.chfocus(curses.A_STANDOUT)
	def refresh_chnlist(self):
		del self.queen.tracker.chnlist[:]
		self.queen.tracker.chnlist_req()
	def increase(self):
		self.queen.min_neighbours += 1
	def decrease(self):
		if self.queen.min_neighbours > 8:
			self.queen.min_neighbours -= 1
	def buffermap_request(self):
		if self.act_pane == self.neighbours_pane:
			try:
				nb = self.neighbours[self.neighbours_pane.curline]
				self.queen.neighbours[nb].buffermap_request()
			except KeyError:
				pass
	def stop(self):
		del self.queen.tracker.peers[:]
		neighbours = self.queen.neighbours.keys()
		for neighbour in neighbours:
			self.queen.neighbours[neighbour].handle_close()
		self.queen.neighbours.clear()
		
		self.asfsrv.chunks.clear()
		self.asfsrv.skipped = 0
		self.asfsrv.pktsizes = ()
		if len(self.asfsrv.asfheader) == 2:
			del self.asfsrv.asfheader[1]
		self.queen.fetchlist.clear()
		
		self.queen.chn_uri = ''
		self.queen.tracker.handle_close()
	def chchannel(self):
		if self.act_pane == self.chnlist_pane:
			self.stop()
			#~ self.queen.tracker.chn_uri = self.queen.chn_uri = self.chnlist[self.chnlist_pane.curline][1]
			#~ self.queen.tracker.channel_register(self.queen.tracker.chn_uri)
			self.queen.chn_uri = self.chnlist[self.chnlist_pane.curline][1]
			#~ self.queen.tracker.handle_close()
