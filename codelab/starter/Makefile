CC     := qcc
FLAGS  := -Vgcc_ntox86_64 -Wall -Wextra -Werror -O2

.PHONY: all clean

all: minimal_resmgr vulnerable.secpol.bin fixed.secpol.bin

minimal_resmgr: minimal_resmgr.c
	$(CC) $(FLAGS) -o $@ $< -lsecpol

vulnerable.secpol.bin: vulnerable.secpol
	secpolcompile -o $@ $<

fixed.secpol.bin: fixed.secpol
	secpolcompile -o $@ $<

clean:
	rm -f minimal_resmgr vulnerable.secpol.bin fixed.secpol.bin
