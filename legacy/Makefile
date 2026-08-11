OBJ += main.o
OBJ += arp_pthread.o
OBJ += arp_link.o
OBJ += ip_pthread.o
OBJ += ip_link.o
OBJ += key_pthread.o
OBJ += get_interface.o

FLAGS = -Wall
CC = gcc

router:$(OBJ)  
	$(CC) $(OBJ) -o $@ $(FLAGS) -lpthread
# %: 匹配任意字符串
%.o:%.c
	$(CC) -c $^ -o $@ $(FLAGS)
# clean: 伪目标
.PHONY:clean
clean:
	rm router *.o -rfv	