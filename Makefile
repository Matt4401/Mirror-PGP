NAME    = my_pgp

all: $(NAME)

$(NAME): main.py
	cp main.py $(NAME)
	chmod +x $(NAME)

clean:
	rm -rf __pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} +

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
