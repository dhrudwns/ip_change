all : ip_change

ip_change: main.o
	g++ -g -o ip_change main.o -lnetfilter_queue

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f ip_change
	rm -f *.o
