# DLL的编写和调用

## DLL

> 动态链接库英文为DLL，是Dynamic Link Library的缩写。DLL是一个包含可由多个程序，同时使用的代码和数据的库。通过使用 DLL，程序可以实现模块化，由相对独立的组件组成。  
> 优势：  
当程序使用 DLL 时，具有以下的优点： 使用较少的资源，当多个程序使用同一个函数库时，DLL 可以减少在磁盘和物理内存中加载的代码的重复量。这不仅可以大大影响在前台运行的程序，而且可以大大影响其他在 Windows 操作系统上运行的程序。 推广模块式体系结构DLL 有助于促进模块式程序的开发。

## 实验目的

完成dll文件的创建与调用，分别使用dumpbin,process explorer,dependency walker进行分析

## 实验要求

1、会编写dll。把.c文件编译为obj文件，把obj文件和lib文件链接为新的dll和lib文件。注意使用def文件定义导出函数。

2、编写一个exe，调用第一步生成的dll文件中的导出函数。方法是（1）link是，将第一步生成的lib文件作为输入文件。（2）保证dll文件和exe文件在同一个目录，或者dll文件在系统目录。

3、第二步调用方式称为load time 特点是exe文件导入表中会出先需要调用的dll文件名及函数名，并且在link 生成exe时，需明确输入lib文件。还有一种调用方式称为 run time。参考上面的链接，使用run time的方式，调用dll的导出函数。包括系统API和第一步自行生成的dll，都要能成功调用。

## 实验过程

### 动态链接

- 增加a.c与b.c文件

```c
//a.c
int main()
{
 sub();
}
```

```c
//b.c
#include<Windows.h>
int sub()
{
 return 0;
}
```

- 点击工具——>应用开发者命令提示进入cmd
![image](./img/img26.png)

- 使用命令`cl.exe /c +xx.c`对a.c与b.c进行编译，生成a.obj、b.obj文件
![image](./img/img27.png)

- 输入以下命令对a.obj和b.obj进行链接，生成test1.exe

``` cmd
link a.obj b.obj /out:test1.exe
```

![image](./img/img28.png)

- 修改b.c中文件如下

```c
#include<Windows.h>
int sub()
{
 MessageBox(0, "msg", 0, 0);
 return 0;
}
```

- 使用命令`cl.exe /c b.c`对b.c进行重新编译

- 使用以下命令对a.obj和b.obj进行链接，生成test2.exe

``` cmd
link a.obj b.obj /out:test2.exe
```

![image](./img/img29.png)

- 由于MessageBox模块在User32.lib中，而没有加上此库进行链接则会引发报错“找不到指定模块”

- 在link时加上User32.lib，此时便可以成功生成test2.exe，双击可弹出messagebox

``` cmd
link a.obj b.obj User32.lib /out:test2.exe
```

![image](./img/img30.png)
![image](./img/img31.png)

- 使用dumpbin分别查看haha.exe和hehe.exe的库,hehe.exe比haha.exe多出来user32.dll这个链接库

``` cmd
dumpbin /imports haha.exe
dumpbin /imports hehe.exe
```

![image](./img/img32.png)
![image](./img/img33.png)

- 使用dependency分别查看haha.exe和hehe.exe的动态链接库调用关系，结果与刚才一致

### load time方式调用dll文件

- 新建项目，添加base.c和exp.def

```c
//base.c
#include<Windows.h>
int intnal_function()
{
    return 0;
}
int lib_function(char* msg)
{
    //do some works
    MessageBoxA(0, "msg from base lib", msg, "OK");
    return 0;
}
```

```c
//exp.def
LIBRARY baselib
EXPORTS
    lib_function
```

对base.c进行编译生成base.obj

```cmd
cl.exe /c base.c
```

![image](./img/img34.png)

- 使用下面的命令对base.obj进行链接

```cmd
link base.obj User32.lib /dll /def:exp.def
```

![image](./img/img35.png)

- 编译app.c生成app.obj

![image](./img/img36.png)

- 将刚刚生成的app.exe链接时需要的base.lib与BASELIB.dll粘贴进app的目录，使用下列命令进行链接

```cmd
link app.obj base.lib /out:app.exe
```

![image](./img/img37.png)

### run time方式调用dll文件

- 新建一个run.c

```c
#include <stdio.h>
#include <windows.h>

typedef int(__cdecl* MYPROC)(LPWSTR);

int main()
{
    HINSTANCE hinstLib;
    MYPROC ProcAdd;
    BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

    // Get a handle to the DLL module.
    hinstLib = LoadLibrary(TEXT("baselib.dll"));
    // baselib.dll不一定放在同一目录下，但调用的路径要保证正确

    // If the handle is valid, try to get the function address.
    if (hinstLib != NULL)
    {
        ProcAdd = (MYPROC)GetProcAddress(hinstLib, "lib_function");

        // If the function address is valid, call the function.
        if (NULL != ProcAdd)
        {
            fRunTimeLinkSuccess = TRUE;
            (ProcAdd)("Run Time: EXE call a DLL");
        }

        // Free the DLL module.
        fFreeResult = FreeLibrary(hinstLib);
    }

    // If unable to call the DLL function, use an alternative.
    if (!fRunTimeLinkSuccess)
        printf("Message printed from executable\n");
    return 0;
}
```

- 编译run.c生成run.obj
![image](./img/img38.png)

- 将之前生成的BASELIB.dll复制到run.c的目录下，使用如下命令进行链接（由于该程序使用运行时动态链接，所以不必将模块与DLL的导入库链接）此时可以在同目录下找到BASELIB.dll，程序链接运行成功

```cmd
link run.obj
```

![image](./img/img39.png)
![image](./img/img40.png)

- 删除BASELIB.dll，重新生成obj和exe文件，再运行时，会打印“Message printed from executable”，说明调用下列代码，链接时失败，但能及时响应错误

```c
if (!fRunTimeLinkSuccess)
    printf("Message printed from executable\n");
```

![image](./img/img41.png)

