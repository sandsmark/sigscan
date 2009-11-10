SRCDIR	= ./src
OBJDIR   = ./obj
BINDIR	= ./bin

CC = colorgcc

BINARY	= $(BINDIR)/sigscan

INCLUDE	= -I ./include 
LDFLAGS = 
CFLAGS = -g -Wunused $(INCLUDE)

VPATH = $(SRCDIR)

OBJECTS = \
	$(OBJDIR)/main.o \
	$(OBJDIR)/handlers.o \

$(OBJDIR)/%.o:	%.c
	$(CC) -c $< $(CFLAGS) -o $@

.PHONY:
all:	make_dirs $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) 

.PHONY:
clean:
	@rm -rvf \
		$(BINARY) \
		$(OBJDIR)/*.o  \

.PHONY:
make_dirs:
	@mkdir -p $(OBJDIR) $(BINDIR)

.PHONY:
install: all
	@if [ -d ~/Dropbox/bin ]; then \
		install -v $(BINARY) ~/Dropbox/bin; \
	else \
		sudo install -v $(BINARY) /usr/local/bin; \
	fi 

