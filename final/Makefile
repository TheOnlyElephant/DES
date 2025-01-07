CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lgmp

# 目录设置
INCLUDE_DIR = include
SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build

# 包含路径
INCLUDES = -I$(INCLUDE_DIR) -I$(INCLUDE_DIR)/sha256 -I$(INCLUDE_DIR)/ecdh -I$(INCLUDE_DIR)/ecdsa

# 源文件
COMMON_SRCS = $(SRC_DIR)/sha256/sha256.c
ECDH_SRCS = $(SRC_DIR)/ecdh/ecdh.c $(SRC_DIR)/ecdh/ecdh_protocol.c
ECDSA_SRCS = $(SRC_DIR)/ecdsa/ecdsa.c

# 测试文件
TEST_ECDH = $(TEST_DIR)/test_ecdh.c
TEST_ECDSA = $(TEST_DIR)/test_ecdsa.c

# 目标文件
COMMON_OBJS = $(COMMON_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
ECDH_OBJS = $(ECDH_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
ECDSA_OBJS = $(ECDSA_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TEST_ECDH_OBJ = $(BUILD_DIR)/tests/test_ecdh.o
TEST_ECDSA_OBJ = $(BUILD_DIR)/tests/test_ecdsa.o

# 可执行文件
ECDH_TEST = $(BUILD_DIR)/test_ecdh
ECDSA_TEST = $(BUILD_DIR)/test_ecdsa

.PHONY: all clean test directories

all: directories $(ECDH_TEST) $(ECDSA_TEST)

# 创建必要的目录
directories:
	@mkdir -p $(BUILD_DIR)/sha256
	@mkdir -p $(BUILD_DIR)/ecdh
	@mkdir -p $(BUILD_DIR)/ecdsa
	@mkdir -p $(BUILD_DIR)/tests

# 编译测试程序
$(ECDH_TEST): $(COMMON_OBJS) $(ECDH_OBJS) $(TEST_ECDH_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(ECDSA_TEST): $(COMMON_OBJS) $(ECDH_OBJS) $(ECDSA_OBJS) $(TEST_ECDSA_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

# 编译源文件
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 编译测试文件
$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: all
	@echo "Running ECDH tests from project root..."
	cd $(shell pwd) && ./$(ECDH_TEST)
	@echo "Running ECDSA tests from project root..."
	cd $(shell pwd) && ./$(ECDSA_TEST)

clean:
	rm -rf $(BUILD_DIR)

install: all
	@mkdir -p /usr/local/include/crypto
	@cp -r $(INCLUDE_DIR)/* /usr/local/include/crypto/
