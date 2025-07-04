CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -Iinclude
LIBS = -lseccomp

SRC_DIR = src
BUILD_DIR = build

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))

EXEC = $(BUILD_DIR)/syscall_monitor

all: $(BUILD_DIR) $(EXEC)

# Cria a pasta build se não existir
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compila cada .c para .o dentro de build/
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Linka o executável dentro de build/
$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
