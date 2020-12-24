#include<stdio.h>
#include<string.h>

int sub(){
	printf("sub\n");
}

int add(int i,int j){
	printf("add=%d",(i+j));
}

int div(int i,char j){
	printf("div=%d",(i/j));
}

int main(){
	
	int (*pf[3])() = {sub,add,div};

	(*pf[0])();
	(*pf[1])(10,4);
	(*pf[2])(10,4);
}
