import idautils
import idaapi
import idc


def guess():
    """
    At the beginning, plugin initiates WinAPI function patterns, for example, 
    CreateFile prototype from MSDN looks like:

    HANDLE CreateFileW(
      [in]           LPCWSTR               lpFileName,
      [in]           DWORD                 dwDesiredAccess,
      [in]           DWORD                 dwShareMode,
      [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
      [in]           DWORD                 dwCreationDisposition,
      [in]           DWORD                 dwFlagsAndAttributes,
      [in, optional] HANDLE                hTemplateFile
    );

    If args usually doesn't contain constans, in pattern they will be replaced
    by zero. In CreateFile pattern usually it's a lpFileNmae, dwShareMode, lpSecurityAttributes
    and hTemplateFile.
    """

    pattern_list = []

    pattern_CreateFile = [0,\
                        [0x0, 0x80000000, 0x40000000, 0x20000000, 0x10000000],\
                        0,\
                        0,\
                        [0x1, 0x2, 0x3, 0x4, 0x5],\
                        [0x0, 0x20, 0x2, 0x80, 0x1000, 0x1, 0x4, 0x100, 0x80000000, 0x02000000, 0x04000000, 0x20000000, 0x00100000, 0x00200000, 0x40000000, 0x01000000, 0x10000000, 0x00800000, 0x08000000],\
                        0,\
                        "maybe CreateFile"]                   
    pattern_list.append(pattern_CreateFile)


    pattern_VirtualAlloc = [0,\
                            0,\
                            [0x1000, 0x2000, 0x3000, 0x6000],\
                            [0x4, 0x10, 0x20, 0x80, 0x40],\
                            "maybe VirtualAlloc"]
    pattern_list.append(pattern_VirtualAlloc)


    pattern_VirtualAllocEx = [0,\
                            0,\
                            0,\
                            [0x1000, 0x2000, 0x3000, 0x6000],\
                            [0x4, 0x10, 0x20, 0x80, 0x40],\
                            "maybe VirtualAllocEx"]
    pattern_list.append(pattern_VirtualAllocEx)
    
    
    pattern_VirtualProtect = [0,\
                        0,\
                        [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x40],\
                        0,\
                        "maybe VirtualProtect"]

    pattern_list.append(pattern_VirtualProtect)


    pattern_CreateProcess = [0,\
                            0,\
                            0,\
                            0,\
                            0,\
                            [0x01000000, 0x04000000, 0x00000010, 0x00000200, 0x08000000,\
                            0x00040000, 0x02000000, 0x00400000, 0x00000800, 0x00001000,\
                            0x00000004, 0x00000400, 0x00000002, 0x00000001, 0x00000008,\
                            0x00080000, 0x00010000],\
                            0,\
                            0,\
                            0,\
                            "maybe CreateProcess"]
    pattern_list.append(pattern_CreateProcess)



    # create combine of two consts in non-zero Args
    # TODO: add to patterns only really used consts because it may be
    # more then combination of two consts

    for pattern in pattern_list:
        for arg in pattern:
            if arg !=0 and type(arg) is not str:
                tmp_arg = []
                for i in range(len(arg)):
                    for n in range(len(arg)):
                        sum = arg[i] + arg[n]
                        if sum not in arg:
                            tmp_arg.append(sum)
                pattern[pattern.index(arg)] = arg + tmp_arg


    pattern_CryptCreateHash = [0,\
                            [0x00006603, 0x00006609, 0x00006611, 0x00006610, 0x00006601,\
                            0x00006604, 0x00002200, 0x00002203, 0x00008009, 0x00008005,\
                            0x00008001, 0x00008002, 0x00008003, 0x00002000, 0x00006602,\
                            0x00006801, 0x00002400, 0x00006802, 0x00008004, 0x00008004,\
                            0x00008008],\
                            0,\
                            0,\
                            0,\
                            "maybe CryptCreateHash"]
    pattern_list.append(pattern_CryptCreateHash)

    pattern_CryptAcquireContextA = [0,\
                                0,\
                                0,\
                                [0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005,\
                                0x00000006, 0x0000000c, 0x0000000d, 0x0000000e, 0x0000000f,\
                                0x00000010, 0x00000011, 0x00000012, 0x00000014, 0x00000015,\
                                0x00000016, 0x00000017, 0x00000018],\
                                [0x00000008, 0x00000010, 0x00000020, 0x00000040, 0xf0000000],\
                                "maybe CryptAcquireContextA"]
    pattern_list.append(pattern_CryptAcquireContextA)


    susp_funcs_list = []


    # Trying to find calls that seems suspicious (calling reg or some memory not in IAT)
    # TODO: add wrapper of jmp instructions

    for ea in idautils.Heads():
        if idc.print_insn_mnem(ea) == "call":
            if idc.get_operand_type(ea, 0) in [1, 3, 4]:    # type o_reg, o_phrase, o_displ
                # sure that it is not already commented
                if ";" not in idc.generate_disasm_line(ea, 0):
                    susp_funcs_list.append(ea)


    # Here begins the search to match pattern and constants to suspicious calls 
    # from binary
    # If it matches the pattern, then a comment is added and the address of possibly
    # guessed API function is displayed in command line output

    for i in susp_funcs_list:
        for pattern in pattern_list:
            instr = idc.prev_head(i)
            arg_index = 0
            pattern_len = len(pattern) - 1      # because last element is name of pattern
            while arg_index < pattern_len:
                if idc.print_insn_mnem(instr) == "push":
                    if idc.get_operand_type(instr, 0) != 5 and pattern[arg_index] != 0:  # type 5 is o_imm
                        break
                    if pattern[arg_index] != 0:     # check arg in pattern
                        try:
                            if idc.get_operand_value(instr, 0) not in pattern[arg_index]:
                                break
                        except:
                            pass
                    arg_index += 1
                elif idc.print_insn_mnem(instr) == "call":
                    break             
                instr = idc.prev_head(instr)                

            if arg_index == len(pattern) - 1:   # because last element is name of pattern
                idc.set_cmt(i, pattern[-1], 1)
                print(f"[+] Added {pattern[-1]} at {hex(i)}")
                
                
    print("[!] No more patterns found")
        
class guess_t(idaapi.plugin_t):
    comment = "Trying to guess hidden WinAPI"
    help = ""
    wanted_name = "can i guess?"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_UNL
    
    def init(self):
        return idaapi.PLUGIN_OK        

    def run(self, arg):
        guess()

    def term(self):
        return

def PLUGIN_ENTRY():
    return guess_t()
