CXX=g++
CXXFLAGS=-Wall -Wextra -g -O1 -std=c++11 -pthread -lboost_system -lboost_filesystem

TARGETS=toreroserve thread_example

all: $(TARGETS)

toreroserve: toreroserve.cpp
	$(CXX) $^ -o $@ $(CXXFLAGS)

thread_example: thread_example.cpp
	$(CXX) $^ -o $@ $(CXXFLAGS)

clean:
	rm -f $(TARGETS)
