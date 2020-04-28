CC = gcc
CFLAGS = -Wall -std=c99 -g
LDFLAGS = -lgmp
SRCDIR = src
BINDIR = bin
OBJDIR = obj
TESTDIR = test

TOOLS = rsa_tools.o rsa_print_tools.o rsa_tools_gmp.o int2char.o
PHASE1 = bezout.o other_base64.o sha256_utils.o sha256.o
PHASE2 = crypt_decrypt.o rsa_file_char.o rsa_files_blocks.o
PHASE4 = rsa_sign.o
OBJTOOLS = $(addprefix $(OBJDIR)/, $(TOOLS))
OBJPHASE1 = $(addprefix $(OBJDIR)/, $(PHASE1))
OBJPHASE2 = $(addprefix $(OBJDIR)/, $(PHASE2))
OBJPHASE4 = $(addprefix $(OBJDIR)/, $(PHASE4))

.PHONY: all clean

all: phase1 phase2_1 phase2_2 phase2_3 phase4

phase1: $(OBJDIR)/phase1.o $(OBJPHASE1) $(OBJTOOLS)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

phase2_1: $(OBJDIR)/phase2_1.o $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

phase2_2: $(OBJDIR)/phase2_2.o $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

phase2_3: $(OBJDIR)/phase2_3.o $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

phase4: $(OBJDIR)/phase4.o $(OBJPHASE4) $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/Sha-256/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(OBJDIR)/%.o: $(TESTDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(BINDIR)/*
	rm -rf Documentation/html/*

doc:
	@doxygen Documentation/Doxyfile
