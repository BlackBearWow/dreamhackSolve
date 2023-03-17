#include <stdio.h>
#include <unistd.h>

int main()
{
	int i=54;
	unsigned char box[0x40] = {};
	read(0, box, sizeof(box));
	for(int i=0; i<0x40; i++)
		printf("Element of index 0x%x is : %d, %02x\n", i, box[i], box[i]);
	printf("%d %02x\n", i, i);
	return 0;
}
