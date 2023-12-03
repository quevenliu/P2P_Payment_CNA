CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lpthread -lssl -lcrypto

SERVER_SRC = server.cpp
CLIENT_SRC = client.cpp
SERVER_TARGET = server
CLIENT_TARGET = client

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)
