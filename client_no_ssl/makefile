CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lpthread

SRC = client.cpp
TARGET = client

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm -f $(TARGET)
