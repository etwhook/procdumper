import winim, cligen , strutils

proc NtOpenProcess(
    ProcessHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ClientId: PCLIENT_ID
): NTSTATUS {.importc, dynlib: "ntdll", stdcall.}

proc getStringFromWideCharArray(wca : array[0..259,WCHAR]): string =
    var final : string = ""
    for byte in wca:
        add(final , chr(byte))
    return final

proc findProcess(procname: string): DWORD =
    var pe32: PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32).DWORD
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , 0)
    Process32First(snapshot , &pe32)
    while Process32Next(snapshot , &pe32):
        let pid = pe32.th32ProcessID
        let name = getStringFromWideCharArray(pe32.szExeFile).LPCSTR
        if lstrcmpA(name, procname.LPCSTR) == 0:
            CloseHandle(snapshot)
            return pid
    return -1
proc dumpProcess(name: string , output: string) =
    let pid = findProcess(name)
    if pid == -1:
        echo("[-] Failed to Find Process.")
        return
    var hProc: HANDLE
    var objAtt: OBJECT_ATTRIBUTES
    var clientId: CLIENT_ID
    clientId.UniqueProcess = pid
    clientId.UniqueThread = 0.DWORD
    InitializeObjectAttributes(&objAtt, NULL , 0 , cast[HANDLE](NULL) , cast[PSECURITY_DESCRIPTOR](NULL))
    let res = NtOpenProcess(&hProc , PROCESS_VM_READ or PROCESS_QUERY_INFORMATION, &objAtt, &clientId)
    if res == 0:
        echo("[+] Success Getting Handle.")
    if hProc == INVALID_HANDLE_VALUE or hProc == 0:
        echo("[-] Failed to Get Handle.")
        return
    let file: HANDLE = CreateFileA(output.LPCSTR, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
    if file == INVALID_HANDLE_VALUE or file == 0:
        echo("[-] Failed to Get File Handle.")
        return
    let dumpOk = MiniDumpWriteDump(hProc, pid, file, cast[MINIDUMP_TYPE](0x00000002), NULL, NULL, NULL)
    if dumpOk == 1:
        echo("[+] Wrote Dump Successfully!")
    else:
        echo("[-] Failed to Dump Process.")
    
when isMainModule:
    dispatch dumpProcess