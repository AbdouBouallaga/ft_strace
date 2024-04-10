NAME = ft_strace
SRC = ./src/ft_strace.c
OBJ	= $(SRC:.c=.o)
# CFLAGS	= -Wall -Wextra -Werror
# CFLAGS	= -Wno-coverage-mismatch
P_HEADER = ./inc/ft_strace.h
# FT_LIB = ./libft/libft.a
FT_LIB =

# all: $(FT_LIB) $(NAME)
all: $(NAME)

# $(FT_LIB): 
	# @make -C  ./libft

$(OBJ): $(SRC) $(P_HEADER)

$(NAME): $(OBJ)
	gcc $(CFLAGS) -o $(NAME) $(OBJ) $(FT_LIB)


clean:
	# @make -C  ./libft clean
	-rm $(OBJ)

fclean: clean
	# @make -C  ./libft fclean
	-rm $(NAME)

re: fclean all

ctests: re
	clear
	gcc -g -o sandbox/a.out ./sandbox/main2.c
	gcc -g -o sandbox/1.out ./sandbox/corr1.c
	gcc -g -o sandbox/2.out ./sandbox/corr2.c
	gcc -g -o sandbox/3.out ./sandbox/corr3.c
	gcc -g -o sandbox/4.out ./sandbox/corr4.c
	gcc -pthread -g -o sandbox/5.out ./sandbox/corr5.c
	gcc -g -o sandbox/6.out ./sandbox/execve.c
	gcc -g -o sandbox/7.out ./sandbox/special_syscall.c
	gcc -g -o sandbox/8.out ./sandbox/write.c

test:
	clear
	gcc -g -o sandbox/a.out ./sandbox/main2.c
	sudo ./ft_strace sandbox/a.out
test1:
	clear
	sudo ./ft_strace sandbox/1.out
test2:
	clear
	sudo ./ft_strace sandbox/2.out
test3: 
	clear
	sudo ./ft_strace sandbox/3.out
test4: 
	clear
	sudo ./ft_strace sandbox/4.out
test5: 
	clear
	sudo ./ft_strace sandbox/5.out
test6: 
	clear
	sudo ./ft_strace sandbox/6.out
test7: 
	clear
	sudo ./ft_strace sandbox/7.out
test8: 
	clear
	sudo ./ft_strace sandbox/8.out
test0: 
	clear
	sudo ./ft_strace sandbox/a.out
