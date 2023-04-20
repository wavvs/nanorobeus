BOFNAME := nanorobeus
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP := strip
OPTIONS := -O3 -masm=intel -Wall -Wextra -g -I include -fno-reorder-functions

.PHONY: all exe bof brc4 cs_bof

all: exe_64 bof cs_bof brc4

exe: exe_64

bof: bof_64 bof_86

cs_bof: cs_bof_64 cs_bof_86

brc4: brc4_64 brc4_86

exe_64: 
	$(CC_x64) source/base64.c source/common.c source/klist.c source/luid.c source/ptt.c source/purge.c \
		source/sessions.c source/entry.c source/tgtdeleg.c source/krb5.c source/kerberoast.c \
		-o dist/$(BOFNAME).x64.exe $(OPTIONS) -l advapi32 -l secur32 -l ntdll \
		-l cryptdll -l msasn1
	$(STRIP) --strip-all dist/$(BOFNAME).x64.exe

bof_64:
	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME).x64.o -DBOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME).x64.o

bof_86:
	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME).x86.o -DBOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME).x86.o

cs_bof_64:
	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME)_cs.x64.o -DBOF -DCS_BOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME)_cs.x64.o

cs_bof_86:
	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME)_cs.x86.o -DBOF -DCS_BOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME)_cs.x86.o

brc4_64:
	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME)_brc4.x64.o -DBRC4 $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME)_brc4.x64.o

brc4_86:
	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME)_brc4.x86.o -DBRC4 $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME)_brc4.x86.o
