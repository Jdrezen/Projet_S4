CC = gcc
CFLAGS = -Wall -std=c99 -g
LDFLAGS = -lgmp
SRCDIR = src
BINDIR = bin
OBJDIR = obj
TESTDIR = test

TOOLS = rsa_tools.o rsa_print_tools.o
PHASE1 = bezout.o other_base64.o sha256_utils.o sha256.o
PHASE2 = crypt_decrypt.o rsa_file_char.o
OBJTOOLS = $(addprefix $(OBJDIR)/, $(TOOLS))
OBJPHASE1 = $(addprefix $(OBJDIR)/, $(PHASE1))
OBJPHASE1 = $(addprefix $(OBJDIR)/, $(PHASE2))

.PHONY: all clean

all: phase1 phase2_1 phase2_2

phase1: $(OBJDIR)/phase1.o $(OBJTOOLS) $(OBJPHASE1)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

phase2_1: $(OBJDIR)/phase2_1.o $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

phase2_1: $(OBJDIR)/phase2_2.o $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/Sha-256%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(OBJDIR)/%.o: $(TESTDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(BINDIR)/*
