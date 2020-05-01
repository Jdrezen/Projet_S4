CC = gcc
CFLAGS = -Wall -std=c99 -g
LDFLAGS = -lgmp
SRCDIR = src
BINDIR = bin
OBJDIR = obj

TOOLS = rsa_tools.o rsa_print_tools.o rsa_tools_gmp.o int2char.o
PHASE1 = bezout.o other_base64.o sha256_utils.o sha256.o
PHASE2 = crypt_decrypt.o rsa_file_char.o rsa_files_blocks.o
PHASE3 = term_canon.o rsa_sign.o rsa_cmd.o
OBJTOOLS = $(addprefix $(OBJDIR)/, $(TOOLS))
OBJPHASE1 = $(addprefix $(OBJDIR)/, $(PHASE1))
OBJPHASE2 = $(addprefix $(OBJDIR)/, $(PHASE2))
OBJPHASE3 = $(addprefix $(OBJDIR)/, $(PHASE3))

.PHONY: all clean

all: main

main: $(OBJDIR)/main.o $(OBJTOOLS) $(OBJPHASE1) $(OBJPHASE2) $(OBJPHASE3)
	$(CC) -o $(BINDIR)/$@ $^ $(LDFLAGS)


$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/Sha-256/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(BINDIR)/*
	rm -rf Documentation/html/*

doc:
	@doxygen Documentation/Doxyfile
