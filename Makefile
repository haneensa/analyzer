TARGET = target # executable with this name

CC = gcc # compiler
LINKER = gcc -o
CFLAGS = -g -O2 -Wall # Compiling flags
LFLAGS = -Wall

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(SOURCES:$(SRCDIR)%.c=$(OBJDIR)%.o)
rm = rm -f

# target: dependencies
# [tab]	<commands>

$(BINDIR)/$(TARGET): $(OBJECTS)
	$(LINKER) $@ $(LFLAGS) $(OBJECTS) -lpcap
	@echo "Linking complete."
	
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ 
	@echo "Compiled"$<"successfully."

clean:
	@$(rm) $(OBJECTS) 
	@echo "Cleanup complete."

.PHONY: remove
remove: clean
	@$(rm) $(BINDIR)/$(TARGET)
	@echo "Executable removed."
