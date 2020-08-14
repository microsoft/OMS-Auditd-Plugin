obj-m += get_offsets.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "Use 'make run' to get the offsets"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
run:
	sudo dmesg -C
	sudo insmod get_offsets.ko
	sudo rmmod get_offsets.ko
	dmesg
