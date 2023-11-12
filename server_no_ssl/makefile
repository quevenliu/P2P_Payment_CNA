CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lpthread

SRC = server.cpp
TARGET = server

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm -f $(TARGET)
