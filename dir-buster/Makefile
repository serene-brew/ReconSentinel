CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -fPIC
LDFLAGS = -lcurl

LIBTARGET = libdirbuster.so
CORE_OBJS = dir_buster.o http_client.o
LIB_OBJS = $(CORE_OBJS) bindings.o

all: $(LIBTARGET)

cli: dir_buster

dir_buster: main.o $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) -o dir_buster main.o $(CORE_OBJS) $(LDFLAGS)

$(LIBTARGET): $(LIB_OBJS)
	$(CXX) -shared -o $(LIBTARGET) $(LIB_OBJS) $(LDFLAGS)

main.o: main.cpp dir_buster.h
	$(CXX) $(CXXFLAGS) -c main.cpp

dir_buster.o: dir_buster.cpp dir_buster.h http_client.h
	$(CXX) $(CXXFLAGS) -c dir_buster.cpp

http_client.o: http_client.cpp http_client.h
	$(CXX) $(CXXFLAGS) -c http_client.cpp

bindings.o: bindings.cpp dir_buster.h
	$(CXX) $(CXXFLAGS) -c bindings.cpp

clean:
	rm -f dir_buster $(LIBTARGET) $(CORE_OBJS) bindings.o main.o

.PHONY: all clean cli
