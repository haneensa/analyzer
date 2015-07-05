TARGET = target # executable with this name

CC = gcc # compiler
LINKER = gcc -o
CFLAGS = -g -O2 -Wall -I. # Compiling flags
LFLAGS = -Wall

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(SOURCES:$(SRCDIR)%.c=$(OBJDIR)%.o)
rm = rm -rf


# target: dependencies
# [tab]	<commands>

$(BINDIR)/$(TARGET): build $(OBJECTS)
	$(LINKER) $@ $(LFLAGS) $(OBJECTS) -lpcap
	@echo "Linking complete."
	
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ 
	@echo "Compiled"$<"successfully."
build:
	@mkdir -p bin
	@mkdir -p obj

clean:
	@$(rm) $(OBJDIR) 
	@echo "Cleanup complete."

.PHONY: remove
remove: clean
	@$(rm) $(OBJDIR) $(BINDIR) $(BINDIR)/$(TARGET)
	@echo "Executable removed."
