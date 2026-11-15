# bcdiff -- function-level x86-64 ELF binary diff.
#
#   make            build build/bcdiff
#   make samples    build the two demo releases
#   make test       run the regression tests
#   make report     run bcdiff on the demo releases and open the HTML

ifeq ($(origin CXX),default)
  CXX := clang++
endif
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wno-unused-parameter
CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?=

# Capstone discovery: pkg-config first, then Homebrew / /usr/local defaults.
# Some capstone.pc files point -I at .../include/capstone, so normalise the
# path to the parent and keep the <capstone/capstone.h> include style.
CAPSTONE_CFLAGS := $(shell pkg-config --cflags capstone 2>/dev/null | sed -e 's/-I\([^ ]*\)\/capstone/-I\1/g' -e 's/-I-I/-I/g')
CAPSTONE_LIBS   := $(shell pkg-config --libs capstone 2>/dev/null)
ifeq ($(strip $(CAPSTONE_LIBS)),)
  CAPSTONE_CFLAGS := -I/opt/homebrew/include -I/usr/local/include
  CAPSTONE_LIBS   := -L/opt/homebrew/lib -L/usr/local/lib -lcapstone
endif
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  CAPSTONE_RPATH := -Wl,-rpath,/opt/homebrew/lib -Wl,-rpath,/usr/local/lib
endif

SRC := src/main.cpp src/util.cpp src/elf.cpp src/disasm.cpp src/features.cpp \
       src/diff.cpp src/report.cpp src/json.cpp
OBJ := $(SRC:src/%.cpp=build/%.o)
DEPS := $(OBJ:.o=.d)

BUILD_DIR := build
BIN := $(BUILD_DIR)/bcdiff

.PHONY: all samples samples-extra large test report clean fmt

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(CAPSTONE_LIBS) $(CAPSTONE_RPATH) $(LDLIBS)

build/%.o: src/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(CAPSTONE_CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

samples:
	./tools/build_samples.sh

samples-extra:
	./tools/build_extra.sh

large:
	./tools/gen_large.sh 400

test: $(BIN) samples
	./tools/build_extra.sh >/dev/null
	./tools/gen_large.sh 400 >/dev/null
	./tools/run_tests.sh

report: $(BIN) samples
	./$(BIN) samples/vuln_app_v1.elf samples/vuln_app_v2.elf -v \
	    --json build/report.json -o build/report.html
	@echo "open build/report.html"

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPS)
