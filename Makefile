# 用户态路由器（嵌入式风格，纯 C11/POSIX）
#
# 常用：
#   make                本地编译（零警告门禁）
#   make CROSS=arm-linux-gnueabihf-   交叉编译（嵌入式板）
#   make TSAN=1         ThreadSanitizer 数据竞争检测
#   make ASAN=1         AddressSanitizer 内存检测
#   make clean

CC      ?= gcc
CROSS   ?=
ifeq ($(CROSS),)
  CC := gcc
else
  CC := $(CROSS)gcc
endif

CFLAGS   = -std=c11 -O2 -D_GNU_SOURCE -Wall -Wextra -Werror -pthread
LDFLAGS  = -pthread

ifeq ($(TSAN),1)
  CFLAGS  += -fsanitize=thread -fno-omit-frame-pointer -g
  LDFLAGS += -fsanitize=thread
endif
ifeq ($(ASAN),1)
  CFLAGS  += -fsanitize=address -fno-omit-frame-pointer -g
  LDFLAGS += -fsanitize=address
endif

SRCS    := $(wildcard src/*.c)
OBJS    := $(SRCS:.c=.o)
TARGET  := router

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

src/%.o: src/%.c src/router.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)

.PHONY: all clean
