#
# Block Cipher Modes of Operation
# @author Dani Huertas
# @email huertas.dani@gmail.com
#
CC = gcc
CFLAGS = -Wall
SHELL = /bin/bash


TEST_PLAIN = 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
# TEST_PLAIN = 6b

AES128_KEY             = 2b7e151628aed2a6abf7158809cf4f3c
AES128_CFB_TEST_CIPHER = 3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
AES128_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES128_OFB_TEST_CIPHER = 3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
AES128_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f


TARGET = kiwiaes128

LIBS =

INCLUDE = -I./src

SOURCES = $(shell find ./src -type f -name '*.c' )

OBJS = $(shell find ./src -type f -name '*.c' | sed -e 's/\.c/\.o/g' -e 's/src\//obj\//g')

all: clean debug

debug: CFLAGS += -g
debug: $(TARGET)

release: CFLAGS += -O2
release: $(TARGET)

depend: _depend

_depend: $(SOURCES)
	rm -f ./.depend
	$(CC) $(CFLAGS) $(INCLUDE) -MM $^ > ./.depend;

obj/%.o: src/%.c
	@mkdir -m 755 -p $$(dirname $@)
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(TARGET)
	./$@ cfb $(TEST_PLAIN) $(AES128_KEY) $(AES128_CFB_TEST_IV) 
	./$@ ofb $(TEST_PLAIN) $(AES128_KEY) $(AES128_OFB_TEST_IV) 


clean:
	@rm -f .depend
	@rm -rf obj
	@rm -rf out
	@rm -rf ./*.out
	@rm -f $(TARGET)
