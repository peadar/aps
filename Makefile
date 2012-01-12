all: aps

OBJS=aps.o pscan.o

clean:
	rm -f aps $(OBJS)

aps: $(OBJS)
	$(CC) -o $@ $(OBJS)
