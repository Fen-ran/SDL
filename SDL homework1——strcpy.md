# strcpy的溢出问题
### 测试代码

```
#define _CRT_SECLRE_NO_WARNINGS //使strcpy函数可以使用

#include<stdlib.h>
#include<stdio.h>
#include<string.h>

int sub(char* x) {
	char y[10];
	strcpy(y, x);
	return 0;
}

int main(int argc, char** argv) { 
	if (argc > 1)
		sub(argv[1]);
	printf("exit");
}
```
### 相关设置
1. ![image](./img1.jpg)


 