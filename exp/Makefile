TARGET     := exploit
LINKSCRIPT := linkscript.lds

CC      := gcc
CFLAGS  := -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector \
	   -no-pie -s -Os -nostdlib -static -Wl,-T$(LINKSCRIPT) -lgcc -Wall

MAIN_C  := src/main.c
SOURCES := \
	consts/log.h \
	consts/prog_regions.h \
	consts/stack.h \
	consts/paging.h \
	consts/msg.h \
	src/nodes_master_and_use.h \
	src/node_free.c \
	src/nodes_decl.h \
	src/nodes_master_and_free.h \
	src/nodes_master_free_use.h \
	src/main.c \
	src/nodes_free_and_use.h \
	src/node_master.c \
	src/node_use.c \
	sys/uio.h \
	sys/msg.h \
	sysutil/clone.h \
	sysutil/mbarrier.h \
	sysutil/pin_cpu.h \
	utils/string.h

ECHO    := echo -e '\t'

RM      := rm -f

CFMT    := clang-format
CFMTFIX := $(CFMT) -i
CFMTCHK := $(CFMT) -n --Werror

.PHONY:
all: $(TARGET)

$(TARGET): $(SOURCES) $(LINKSCRIPT)
	@$(ECHO) CC $(TARGET)
	@$(CC) -o $(TARGET) $(MAIN_C) $(CFLAGS)

.PHONY:
clean:
	@$(ECHO) RM $(TARGET)
	@$(RM) $(TARGET)

.PHONY:
fmt:
	@$(ECHO) FMT $(SOURCES)
	@$(CFMTFIX) $(SOURCES)

.PHONY:
check:
	@$(ECHO) CHECK $(SOURCES)
	@$(CFMTCHK) $(SOURCES)
