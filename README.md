# can_I_guess

Yet another simple IDAPython plugin that can help find usage patterns for dynamically obtained addresses of WinAPI functions based on the search for constants specific to the corresponding WinAPI function.



### For example, suspicious call can look like:
```
push  40h
push  3000h
push  800h
push  0
push  edi
call  esi
```

which looks like a call to VirtualAllocEx , which we can understand by looking at the last two arguments and comparing them with the corresponding constants from the [official documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), and also by comparing the total number of arguments.

### Efficiency

This plugin can be useful at the beginning of the analysis of malicious code in order to tell the analyst where and what exactly can be used. The plugin does not always work correctly, sometimes it makes a mistake with identifying a suspicious call.
At the same time, the plug-in is based on the analyst's personal experience regarding what calls and how they can look like when they are dynamically resolved.


Of course, if an attacker has added a more complex argument passing mechanism without using opcodes directly with WinAPI constants, the plugin will not reveal anything. 
At the same time, my experience of using the plugin shows that in many average samples, this simple pattern of calling suspicious functions is used.



### TODO:
implement a version for x64 (i.e. for __fastcall x64);
implement a version for __fastcall in x86 and __thiscall;
continue filling and improving the database of patterns.
