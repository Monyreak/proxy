# Compiler and compiler flags
CXX = g++
CXXFLAGS = -Wall -g -std=c++11
LDFLAGS = -lssl -lcrypto -lpthread # Add linker flags for OpenSSL libraries

# Define the source, binary, and executable directories
SRC_DIR = src
BIN_DIR = bin

# Target executable names
PROXY_TARGET = $(BIN_DIR)/myproxy

# Source files
PROXY_SRC = $(SRC_DIR)/myproxy.cpp

# Default target
all: $(PROXY_TARGET)

$(PROXY_TARGET): $(PROXY_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) 
	
# Clean target for cleaning up the directory
clean:
	rm -rf $(BIN_DIR)/*

.PHONY: all clean
