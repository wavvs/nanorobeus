BOFNAME := nanorobeus
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP := strip
OPTIONS := -O3 -masm=intel -Wall -I include

nanorobeus: 
	$(CC_x64) source/base64.c source/common.c source/klist.c source/luid.c source/ptt.c source/purge.c \
		source/sessions.c source/entry.c -o dist/$(BOFNAME).x64.exe $(OPTIONS) -l advapi32 -l secur32
	$(STRIP) --strip-all dist/$(BOFNAME).x64.exe
	
	$(CC_x86) source/base64.c source/common.c source/klist.c source/luid.c source/ptt.c source/purge.c \
		source/sessions.c source/entry.c -o dist/$(BOFNAME).x86.exe $(OPTIONS) -l advapi32 -l secur32
	$(STRIP) --strip-all dist/$(BOFNAME).x86.exe

	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME).x64.o -DBOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME).x64.o

	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME).x86.o -DBOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME).x86.o

	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME)_brc4.x64.o -DBRC4 $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME)_brc4.x64.o

	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME)_brc4.x86.o -DBRC4 $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME)_brc4.x86.o
