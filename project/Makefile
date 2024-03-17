OBJ = main.o external.o

testy: ${OBJ}
	${CC} -o $@ $^

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $<

clean:
	rm *.o testy
