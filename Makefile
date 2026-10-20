CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic

all: elf-analyzer

elf-analyzer: elf_analyzer.cpp
	$(CXX) $(CXXFLAGS) elf_analyzer.cpp -o elf-analyzer

clean:
	rm -f elf-analyzer

.PHONY: all clean
