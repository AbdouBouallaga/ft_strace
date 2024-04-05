NAME = ft_strace
SRC = ./src/ft_strace.c
OBJ	= $(SRC:.c=.o)
# CFLAGS	= -Wall -Wextra -Werror
CFLAGS	= -Wno-coverage-mismatch
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

test: all
	clear
	gcc -o sandbox/a.out ./sandbox/main2.c
	./ft_strace sandbox/a.out