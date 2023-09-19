# IdaDump2.0
上述代码适用于 IDA Pro 7.x 版本w
代码主要用于32位和64位ELF程序的导出，但在具体的使用中可能需要根据目标程序的架构进行适当的调整
1.判断文件是否elf
2.判断文件是否为ELF文件的功能，您可以使用Python的magic库来检查文件的魔术数字（Magic Number）是否与ELF文件的魔术数字匹配。ELF文件的魔术数字通常是0x7F454C46或0x464C457F。
3.在 run 方法，通过 idaapi.AskLong 来获取用户输入的地址，调用 export_elf_segments，如果 export_address为true，则导出该地址的数据到目的文件，如果为null，则遍历elf文件所有段到目的文件
