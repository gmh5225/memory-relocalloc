### RelocAlloc: Using .reloc section to replace the typical allocation calls 
<br>

### Explaining the code:
- We first, locate the addresses of all the dlls mapped to our process.
- We then construct an array of structs and we fill it up with some data, thats **Initialize()** function.
- Now, we have a full array, next step is to search for the right address.
- calling **GetSuitableAddress(SIZE_T ShellcodeSize)** will do the job; thats finding us the right code cave (empty place in memory, fitting the shellcode size)
- in case it is found it will be returned.
- to use it we **must adjust** memory protection to be writable/executable ... (the poc is directly rwx)
<br>

### Demo:
![img1](https://gitlab.com/ORCA666/relocalloc/-/raw/main/images/demo1.png)
![img2](https://gitlab.com/ORCA666/relocalloc/-/raw/main/images/demo2.png)
<br>
#### Note: this only work with small shellcodes, bcz it depends on the dlls mapped, the bigger the .reloc section, the bigger chances of getting a valid address. In addition, this is tested only on a `x64` machine, but it should work for x86 (i think :p)

<br><br>
<h6 align="center"> <i>#                                   STAY TUNED FOR MORE</i>  </h6> 
![120064592-a5c83480-c075-11eb-89c1-78732ecaf8d3](https://gitlab.com/ORCA666/kcthijack/-/raw/main/images/PP.png)



