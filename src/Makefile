TGT=dialhp
SRCS=$(wildcard *.cpp)

LIBRAYS= ../lib/udt4/libudt.a -lrt -pthread -lssl -lcrypto -ldl -lz ../lib/libdns.a ../lib/libjansson.a ../lib/libclib.a -lresolv 

COMPILE_FLAGS= -g -W -O2 -I../include -I../clib/include

CC=g++

all:$(TGT)
	cp $(TGT) ../
	@echo Generation target!	

$(TGT):$(SRCS:.cpp=.o)
	$(CC) -o $@ $^ $(LIBRAYS) $(COMPILE_FLAGS) 
	
%.o : %.cpp
	$(CC) -c $(COMPILE_FLAGS) $< -o $@
	
clean:
	rm -rf $(TGT) $(SRCS:.cpp=.o) .*.swp
