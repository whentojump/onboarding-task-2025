.PHONY: clean all

all: kernel-postprocess

kernel-postprocess: kernel-postprocess.cpp
	g++ kernel-postprocess.cpp -o kernel-postprocess

clean:
	rm -f *.elf *.disassembly.txt *.trace.txt *.trace.bin *.trace.bin2 kernel-postprocess
