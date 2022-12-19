CC = ~/AFLplusplus/afl-clang-lto
TARGET = fuzzme
CFLAGS = 
# CC = gcc
# CFLAGS = -fsanitize=address -fno-sanitize-recover=all -g 
# TARGET = fuzzme_test
LDFLAGS = -lfreerdp3 -lwinpr3 -lfreerdp-client3


OBJS = rdpgfx_common.o rdpgfx_codec.o rdpgfx_main.o main.o 


$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(CFLAGS)

rdpgfx_common.o: rdpgfx_common.h rdpgfx_common.c
	$(CC) -c -o rdpgfx_common.o rdpgfx_common.c $(LDFLAGS) $(CFLAGS)

rdpgfx_main.o: rdpgfx_common.h rdpgfx_codec.h rdpgfx_codec.c
	$(CC) -c -o rdpgfx_codec.o rdpgfx_codec.c $(LDFLAGS)  $(CFLAGS)

rdpgfx_main.o: rdpgfx_common.h rdpgfx_codec.h rdpgfx_main.h rdpgfx_main.c
	$(CC) -c -o rdpgfx_main.o rdpgfx_main.c $(LDFLAGS) $(CFLAGS)

main.o: rdpgfx_main.h main.c
	$(CC) -c -o main.o main.c $(LDFLAGS) $(CFLAGS)

clean:
	rm -f *.o 
	rm -f $(TARGET)