# Tunnel
# -------------------------------------
# file       : Makefile
# author     : Ben Kietzman
# begin      : 2024-08-23
# copyright  : kietzman.org
# email      : ben@kietzman.org

prefix=/usr/local

all: bin/tunnel

bin/tunnel: obj/tunnel.o bin
	g++ -o bin/tunnel obj/tunnel.o -lssh

bin:
	if [ ! -d bin ]; then mkdir bin; fi;

obj/tunnel.o: tunnel.cpp obj
	g++ -ggdb -Wall -c tunnel.cpp -o obj/tunnel.o

obj:
	if [ ! -d obj ]; then mkdir obj; fi;

install: bin/tunnel $(prefix)/bin
	install --mode=755 bin/tunnel $(prefix)/bin/
	if [ ! -f /etc/systemd/user/tunnel.service ]; then install --mode=644 tunnel.service /etc/systemd/user/; fi;

$(prefix)/bin:
	mkdir $(prefix)/bin

clean:
	-rm -fr bin obj
