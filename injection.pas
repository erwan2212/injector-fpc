unit injection;

interface

uses windows,ntdll,
  instdecode in '..\ddetours\delphi-detours-library-master\Source\instdecode.pas';

//function Inject_RemoteThreadCODE(ProcessHandle: longword; EntryPoint: pointer):boolean;
function Inject_RemoteThreadDLL(ProcessHandle: longword; dll: string):boolean;

function InjectRTL_CODE(ProcessHandle: longword; EntryPoint,param: pointer):boolean;
function InjectRTL_DLL(ProcessHandle: longword; dll:string):boolean;
function EjectRTL_DLL(ProcessHandle: longword; hmod:thandle):boolean;

//function InjectNT_CODE(ProcessHandle: longword; EntryPoint: pointer):boolean;
function InjectNT_DLL(ProcessHandle: longword; dll: string):boolean;

//function injectapc( hprocess,hthread:thandle;dll:string):boolean;
function injectctx(hprocess, hthread: thandle; dll: string): boolean;


//var

{
TNtCreateThreadEx : function(
  ThreadHandle: PHANDLE;
  DesiredAccess: ACCESS_MASK;
  ObjectAttributes: Pointer;
  ProcessHandle: THANDLE;
  lpStartAddress: Pointer;
  lpParameter: Pointer;
  CreateSuspended: BOOL;
  dwStackSize: DWORD;
  SizeOfStackCommit: Pointer;
  SizeOfStackReserve: Pointer;
  Thebuf: Pointer): HRESULT; stdcall;
  }


  {//incorrect?
__NtCreateThreadEx: function (
  var hThread: Cardinal;
  DesiredAccess: Cardinal;
  lpThreadAttribtes: Pointer;
  hProcess: Cardinal;
  lpStartAddress,
  lpParameter: Pointer;
  CreateSuspended: Boolean;
  dwStackZeroBits,
  SizeOfStackCommit,
  SizeOfStackReserve: Cardinal;
  var Thebuf: NT_THREAD_BUFFER): Cardinal; stdcall = nil;
  }

   {
   function QueueUserAPC(
   pfnAPC:pointer; //PAPCFUNC
   hThread:THANDLE;
   dwData:nativeuint //ULONG_PTR
  ):dword; stdcall;external 'kernel32.dll';
  }
  
implementation

uses SysUtils;

function Align_(Value, Align: Cardinal): Cardinal;
begin
  if ((Value mod Align) = 0) then
    Result := Value
  else
    Result := ((Value + Align - 1) div Align) * Align;
end;

function AllocMemAlign(const ASize, AAlign: Cardinal; out AHolder: Pointer): Pointer;
var
  Size: Cardinal;
  Shift: NativeUInt;
begin
  if AAlign <= 1 then
  begin
    AHolder := AllocMem(ASize);
    Result := AHolder;
    Exit;
  end;

  if ASize = 0 then
  begin
    AHolder := nil;
    Result := nil;
    Exit;
  end;

  Size := ASize + AAlign - 1;

  AHolder := AllocMem(Size);

  Shift := NativeUInt(AHolder) mod AAlign;
  if Shift = 0 then
    Result := AHolder
  else
    Result := Pointer(NativeUInt(AHolder) + (AAlign - Shift));
end;


{
function injectapc( hprocess,hthread:thandle;dll:string):boolean;
var
    lpDllAddr,lploadLibraryAddr:pointer;
    byteswritten:nativeuint;
begin
    //memory address for dll
    lpDllAddr := VirtualAllocEx(hProcess, nil, length(dll), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, lpDllAddr, @dll[1], length(dll), byteswritten); // write dll path
    if byteswritten =0 then exit;
    OutputDebugString(pchar('lpDllAddr:'+inttohex(nativeuint(lpDllAddr),8)+' '+inttostr(byteswritten )+' written'));
    //memory address of loadlibrary
    lploadLibraryAddr := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
    OutputDebugString(pchar('loadLibraryAddress:'+inttohex(nativeuint(lploadLibraryAddr),8)));
    //
    if QueueUserAPC(GetProcAddress(LoadLibraryA('kernel32.dll'), 'LoadLibraryA'), hThread, nativeuint(lpDllAddr))=0
       then result:=false
       else result:=true;
end;
}

function injectctx(hprocess, hthread: thandle; dll: string): boolean;
const
{$IFDEF win64}
  code:array [0..62] of byte =
    // sub rsp, 28h
    ($48, $83, $ec, $28,
    // mov [rsp + 18h], rax
    $48, $89, $44, $24, $18,
    // mov [rsp + 10h], rcx
    $48, $89, $4c, $24, $10,
    // mov rcx, 11111111111111111h  -> DLL
    $48, $b9, $11, $11, $11, $11, $11, $11, $11, $11,
    // mov rax, 22222222222222222h  -> Loadlibrary
    $48, $b8, $22, $22, $22, $22, $22, $22, $22, $22,
    // call rax
    $ff, $d0,
    // mov rcx, [rsp + 10h]
    $48, $8b, $4c, $24, $10,
    // mov rax, [rsp + 18h]
    $48, $8b, $44, $24, $18,
    // add rsp, 28h
    $48, $83, $c4, $28,
    // mov r11, 333333333333333333h  -> RIP
    $49, $bb, $33, $33, $33, $33, $33, $33, $33, $33,
    // jmp r11
    $41, $ff, $e3);
  {$endif}
  {$IFDEF win32}
      code:array [0..21] of byte =
      ($68, $DE, $AD, $BE, $EF, // push $DEADBEEF EIP
      $9c,             //pushfd
      $60,             //pushad
      $68, $DE, $AD, $BE, $EF, //push $DEADBEEF // memory with dll name
      $b8, $DE, $AD, $BE, $EF, //mov eax, $DEADBEEF // loadlibrary address
      $ff, $d0,          //call eax
      $61,             //popad
      $9d,             //popfd
      $c3);             //ret
  {$endif}
var
  lpDllAddr, stub, lploadLibraryAddr: pointer;
   dwdlladdr, dwloadlibraryaddr: nativeuint;
  oldip,byteswritten: nativeuint;
  ctx: PContext;
  Storage: Pointer;
  i:byte;
  tmp:string;
begin
  result:=false;
  OutputDebugString (pchar('hprocess:'+inttostr(hprocess)));
  OutputDebugString (pchar('hthread:'+inttostr(hthread)));
  //if ntsuspendprocess(hprocess)=false then
  if SuspendThread(hthread)=-1 then
     begin
     outputdebugstring(pchar('suspend failed: '+inttostr(getlasterror)));
     exit;
     end;

  //memory address for dll
  lpDllAddr := VirtualAllocEx(hProcess, nil, length(dll), MEM_COMMIT, PAGE_READWRITE);
  if lpDllAddr = nil then
  begin
       outputdebugstring(pchar('lpDllAddr is null:'+inttostr(getlasterror)));
       exit;
  end;
  dwdlladdr := nativeuint(lpDllAddr);
  OutputDebugString(PChar('lpDllAddr:' + inttohex(nativeuint(lpDllAddr), 8)));
  WriteProcessMemory(hProcess, lpDllAddr, @dll[1], length(dll), byteswritten);
  if (byteswritten <> length(dll)) or (byteswritten = 0) then
  begin
     outputdebugstring(pchar('WriteProcessMemory failed'));
     exit;
  end;

  //memory address of code in the remote process
  stub := VirtualAllocEx(hProcess, nil, length(code ), MEM_COMMIT,PAGE_EXECUTE_READWRITE);
  if stub = nil then
  begin
       outputdebugstring(pchar('stub is null'));
       exit;
  end;
  OutputDebugString(PChar('stub:' + inttohex(nativeuint(stub), 8)));

  //memory address of loadlibrary
  lploadLibraryAddr := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
  dwloadlibraryaddr := nativeuint(lploadLibraryAddr);
  OutputDebugString(PChar('loadLibraryAddress:' + inttohex( nativeuint(lploadLibraryAddr), 8)));

  //old context
  {$IFDEF win64}ctx := AllocMemAlign(SizeOf(TContext), 16, Storage);{$endif}
  {$IFDEF win32}ctx := AllocMemAlign(SizeOf(TContext), 0, Storage);{$endif}
  ctx^.ContextFlags := CONTEXT_CONTROL;
  if GetThreadContext(hThread, ctx^)=false then
  begin
       outputdebugstring(pchar('GetThreadContext failed:'+inttostr(getlasterror)));
       exit;
  end;
  {$IFDEF win64}oldIP := ctx^.Rip;{$endif}
  {$IFDEF win32}oldIP := ctx^.eip;{$endif}
  OutputDebugString(PChar('oldip:' + inttohex(nativeuint(oldip), 8)));

  //modify code with correct memory addresses
  //RIP + dwdlladdr + dwloadlibraryaddr
  {$IFDEF win64}
  copymemory(@code [$34], @oldip, sizeof(nativeuint));
  copymemory(@code [$10], @dwdlladdr, sizeof(nativeuint));
  copymemory(@code [$1a], @dwloadlibraryaddr, sizeof(nativeuint));
  {$endif}
  {$IFDEF win32}
  copymemory(@code [1], @oldip, sizeof(nativeuint));
  copymemory(@code [8], @dwdlladdr, sizeof(nativeuint));
  copymemory(@code [13], @dwloadlibraryaddr, sizeof(nativeuint));
  {$endif}
  //write code to remote process
  WriteProcessMemory(hProcess, stub, @code[0], length(code ), byteswritten);
  if (byteswritten<>length(code )) or (byteswritten = 0) then
  begin
     outputdebugstring(pchar('WriteProcessMemory failed'));
     exit;
  end;

  //update context
  {$IFDEF win64}ctx^.rip := nativeuint(stub);{$endif}
  {$IFDEF win32}ctx^.eip := nativeuint(stub);{$endif}
  if SetThreadContext(hThread, ctx^)=false then
  begin
   outputdebugstring(pchar('SetThreadContext failed:'+inttostr(getlasterror)));
   exit;
  end else outputdebugstring(pchar('SetThreadContext OK'));

  //for i:=0 to length(codeX64_2 )-1 do tmp:=tmp+ (inttohex(codeX64_2[i],2)+' ');

  if ResumeThread(hthread)=-1 then
  //if ntresumeprocess(hprocess)=false then
   begin
     outputdebugstring(pchar('resume failed: '+inttostr(getlasterror)));
     exit;
   end else outputdebugstring(pchar('resume OK: '+inttostr(getlasterror)));

  result:=true;
  end;

function Inject_RemoteThreadDLL(ProcessHandle: longword; dll:string):boolean;
var
baseaddress: Pointer=nil;
  Size, BytesWritten, TID: longword;
  NtStatus:integer;
  //ClientID:CLIENT_ID ;
  hthread:thandle;
  Status:integer;
  dw:dword;
  exitcode:dword;
begin
result:=false;
  OutputDebugString(pchar('*** Inject_RemoteThreadDLL ***:'+inttostr(ProcessHandle)));
  OutputDebugString(pchar('ProcessHandle:'+inttostr(ProcessHandle)));
  SetLastError(0);
  size:=length(dll)+sizeof(char);
  size:=align(size,$1000); //needed for NtAllocateVirtualMemory
  status:=NtAllocateVirtualMemory(ProcessHandle ,@baseaddress,0,@Size,MEM_COMMIT , PAGE_READWRITE);
  //baseaddress :=VirtualAllocEx(ProcessHandle ,nil,size,MEM_COMMIT or MEM_RESERVE , PAGE_EXECUTE_READWRITE);
  OutputDebugStringA(pchar('VirtualAllocEx:'+inttohex(nativeuint(baseaddress),8)));
  if status<>0 then
  //if baseaddress=nil then
    begin
    OutputDebugString(pchar('InjectRTL_DLL, NtAllocateVirtualMemory failed,'+inttohex(status,4)));
    raise Exception.Create('InjectRTL_DLL, NtAllocateVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    exit;
    end;

  //b:=WriteProcessMemory(ProcessHandle, NewModule, Module, Size, BytesWritten);
  //if b=false
  Status:=NtWriteVirtualMemory(ProcessHandle, baseaddress, @dll[1], size, @BytesWritten);
  if Status<>0
    then
    begin
    OutputDebugString(pchar('NtWriteVirtualMemory failed,'+inttohex(status,4)));
    raise Exception.Create('NtWriteVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    end;
  OutputDebugString(pchar('LoadLibraryA:'+inttohex(nativeuint(GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA')),sizeof(nativeuint))));
  hthread:= CreateRemoteThread(ProcessHandle, nil, 0, GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA'), baseaddress , 0, TID);
  OutputDebugString(pchar('hthread:'+inttostr(hthread)));
  OutputDebugString(pchar('tid:'+inttostr(tid)));
  if  hthread<>0 then result:=true;
  dw:=WaitForSingleObject(hThread,10000);
  OutputDebugString(pchar('WaitForSingleObject:'+inttohex(dw,sizeof(dw))));
  GetExitCodeThread(hThread ,exitcode);
  OutputDebugString(pchar('GetExitCodeThread:'+inttohex(exitcode,sizeof(exitcode))));
  CloseHandle(hthread);
  //VirtualFreeEx(ProcessHandle, baseaddress, Size, MEM_RELEASE);
  NtFreeVirtualMemory (ProcessHandle,@baseaddress ,@size,MEM_RELEASE);
end;


function Inject_RemoteThreadCODE(ProcessHandle: longword; EntryPoint: pointer):boolean;
var
  Module, NewModule: Pointer;
  Size, TID: longword;
  BytesWritten:uint;
  NtStatus:integer;
  //ClientID:CLIENT_ID ;
  hthread:thandle;
begin
result:=false;
  Module := Pointer(GetModuleHandle(nil));
  Size := PImageOptionalHeader(Pointer(integer(Module) + PImageDosHeader(Module)^._lfanew + SizeOf(dword) + SizeOf(TImageFileHeader)))^.SizeOfImage;
  size:=align(size,$1000);
  VirtualFreeEx(ProcessHandle, Module, 0, MEM_RELEASE);
    //begin
    //raise Exception.Create('VirtualFreeEx failed,'+inttostr(getlasterror));
    //result:=false;
    //exit;
    //end;
  NewModule := VirtualAllocEx(ProcessHandle, Module, Size, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if newmodule=nil then
    begin
    raise Exception.Create('VirtualAllocEx failed,'+inttostr(getlasterror));
    result:=false;
    exit;
    end;
  //Status:=NtWriteVirtualMemory(ProcessHandle, NewModule, module, size, @BytesWritten);
  //if status<>0 then
  if WriteProcessMemory(ProcessHandle, NewModule, Module, Size, @BytesWritten)=false then
    begin
    raise Exception.Create('WriteProcessMemory failed,'+inttostr(getlasterror));
    result:=false;
    exit;
    end;
  hthread:= CreateRemoteThread(ProcessHandle, nil, 0, EntryPoint, Module, 0, TID);
  if  hthread<>0 then result:=true;
  WaitForSingleObject(hthread,INFINITE);
  CloseHandle(hthread);
end;

procedure decode(param:pointer);
var
  Inst: TInstruction;
  nInst: Integer;
  tmp:string;
  i:byte;
  p:pointer;
begin
  Inst := Default (TInstruction);
    Inst.Archi := CPUX  ;
    Inst.NextInst := param ;
    nInst := 0;
    Inst.Addr := Inst.NextInst; // added
  while (Inst.OpCode <> $c3) do
  begin
    inc(nInst);
    //Inst.Addr := Inst.NextInst; //removed
    DecodeInst(@Inst);
    //Writeln(Format('OpCode : 0x%.2x | Length : %d', [Inst.OpCode, Inst.InstSize]));

  //if inst.InstSize>1 then
    begin
    tmp:='';
    for i:=0 to inst.InstSize-1  do
      begin
      p:=pointer(nativeuint(Inst.Addr)+i);
      tmp:=tmp+inttohex(byte(p^),2);
      end;
     writeln(tmp);
    end;

   //inst.Addr :=pointer(nativeint(inst.Addr)+inst.InstSize ); //added
   Inst.Addr := Inst.NextInst;                                 //added
  end;
end;

//https://msdn.microsoft.com/en-us/library/cc704588.aspx -> status codes
function InjectRTL_CODE(ProcessHandle: longword; EntryPoint,param: pointer):boolean;
var
  Module, baseaddress,paramaddress: Pointer;
  Size,size2, BytesWritten, TID: longword;
  Status:integer;
  hThread:thandle;
  ClientID:CLIENT_ID;
  b:boolean;
begin
  OutputDebugString('InjectRTL_CODE');
  //
  //decode(@NtAllocateVirtualMemory);
  //exit;
  //
  //STATUS_FREE_VM_NOT_AT_BASE=0xC000009F
  //STATUS_UNABLE_TO_DELETE_SECTION=0xC000001B
  
  Module := Pointer(GetModuleHandle(nil));
  OutputDebugString(pchar('Module:'+inttohex(nativeuint(Module),sizeof(Module))));
  OutputDebugString(pchar('EntryPoint:'+inttohex(nativeuint(EntryPoint),sizeof(EntryPoint))));
  OutputDebugString(pchar('Param:'+inttohex(nativeuint(Param),sizeof(Param))));
  size:=0;status:=0;
  b:=VirtualFreeEx(ProcessHandle, Module, 0, MEM_RELEASE);
  OutputDebugString(pchar('VirtualFreeEx:'+booltostr(b)));
  //status:=NtFreeVirtualMemory(ProcessHandle, @module, @size, MEM_RELEASE);
  {
  if status<>0 then
    begin
    raise Exception.Create('NtFreeVirtualMemory $'+inttohex(integer(module),4)+' failed,'+inttohex(status,4));
    result:=false;
    exit;
    end;
  }
  Size := PImageOptionalHeader(Pointer(nativeuint(Module) + PImageDosHeader(Module)^._lfanew + SizeOf(dword) + SizeOf(TImageFileHeader)))^.SizeOfImage;
  size:=align(size,$1000);
  OutputDebugString(pchar('size:'+inttostr(size)));
  SetLastError(0);

  //STATUS_INVALID_HANDLE=C0000008
  //baseaddress :=VirtualAllocEx(ProcessHandle ,module,size,MEM_COMMIT or MEM_RESERVE , PAGE_EXECUTE_READWRITE);
  baseaddress:=module;
  status:=NtAllocateVirtualMemory(ProcessHandle ,@baseaddress,0,@Size,MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  OutputDebugString(pchar('NtAllocateVirtualMemory:'+inttostr(status)));
  OutputDebugString(pchar('baseaddress:'+inttohex(nativeuint(baseaddress),sizeof(baseaddress))));
  //if baseaddress =nil then
  if status<>0 then
    begin
    raise Exception.Create('NtAllocateVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    exit;
    end;

  paramaddress:=nil;
  size2:=align(16,$1000);
  if param<>nil then status:=NtAllocateVirtualMemory(ProcessHandle ,@paramaddress,0,@Size2,MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  OutputDebugString(pchar('NtAllocateVirtualMemory:'+inttostr(status)));
  OutputDebugString(pchar('paramaddress:'+inttohex(nativeuint(paramaddress),sizeof(paramaddress))));
  //if baseaddress =nil then
  if status<>0 then
    begin
    raise Exception.Create('NtAllocateVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    exit;
    end;

  //lets write our module to baseaddress
  Status:=NtWriteVirtualMemory(ProcessHandle, baseaddress, Module, Size, @BytesWritten);
  OutputDebugString(pchar('NtWriteVirtualMemory:'+inttostr(status)));
  if Status<>0
    then
    begin
    raise Exception.Create('NtWriteVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    end
    else
    begin
    //Status:=RtlCreateUserThread(ProcessHandle, nil, false, 0, 0,0, GetProcAddress (GetModuleHandle('dll'),'func') , pchar('param'), @hThread, @ClientID);

    //size=16 is arbitrary...
    if param<>nil then Status:=NtWriteVirtualMemory(ProcessHandle, paramaddress, param, 16, @BytesWritten);
    OutputDebugString(pchar('NtWriteVirtualMemory:'+inttostr(status)));
    //messageboxa(0,'wait','wait',0);
    Status:=RtlCreateUserThread(ProcessHandle, nil, false, 0, 0,0, EntryPoint , paramaddress , @hThread, @ClientID);
    OutputDebugString(pchar('RtlCreateUserThread:'+inttostr(status)));
    WaitForSingleObject(hThread,INFINITE);
    CloseHandle(hThread);
    if Status <>0 then result:=false else result:=true;
    end;

    size2:=0;size:=0; //If the MEM_RELEASE flag is set in *FreeType, *RegionSize must be zero
    if baseaddress<>nil then NtFreeVirtualMemory(ProcessHandle, @baseaddress, @size, MEM_RELEASE);
    if paramaddress<>nil then NtFreeVirtualMemory(ProcessHandle, @paramaddress, @size2, MEM_RELEASE);

end;



function InjectRTL_DLL(ProcessHandle: longword; dll:string):boolean;
const
ThreadDynamicCodePolicy =2;
type TGetThreadInformation=function(hThread:thandle;
  ThreadInformationClass:dword;
  ThreadInformation:pointer;
  ThreadInformationSize:DWORD):boolean;stdcall;
var
  baseaddress: Pointer=nil;
  Size, BytesWritten, TID: ulong;
  dw:dword;
  Status:integer;
  hThread:thandle;
  ClientID:CLIENT_ID ;
  b:boolean;
  GetThreadInformation:tGetThreadInformation;
  dwThreadPolicy:dword;
  exitcode:dword;
begin
  SetLastError(0);
  OutputDebugString(pchar('*** InjectRTL_DLL ***:'+inttostr(ProcessHandle)));
  OutputDebugString(pchar('ProcessHandle:'+inttostr(ProcessHandle)));
  size:=length(dll)+sizeof(char);
  size:=align(size,$1000); //needed for NtAllocateVirtualMemory
  status:=NtAllocateVirtualMemory(ProcessHandle ,@baseaddress,0,@Size,MEM_COMMIT or MEM_RESERVE , PAGE_READWRITE);
  //baseaddress :=VirtualAllocEx(ProcessHandle ,nil,size,MEM_COMMIT or MEM_RESERVE , PAGE_EXECUTE_READWRITE);
  OutputDebugStringA(pchar('VirtualAllocEx:'+inttohex(nativeuint(baseaddress),8)));
  if status<>0 then
  //if baseaddress=nil then
    begin
    OutputDebugString(pchar('InjectRTL_DLL, NtAllocateVirtualMemory failed,'+inttohex(status,4)));
    raise Exception.Create('InjectRTL_DLL, NtAllocateVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    exit;
    end;

  //b:=WriteProcessMemory(ProcessHandle, NewModule, Module, Size, BytesWritten);
  //if b=false
  Status:=NtWriteVirtualMemory(ProcessHandle, baseaddress, @dll[1], size, @BytesWritten);
  if Status<>0
    then
    begin
    OutputDebugString(pchar('NtWriteVirtualMemory failed,'+inttohex(status,4)));
    raise Exception.Create('NtWriteVirtualMemory failed,'+inttohex(status,4));
    result:=false;
    end
    else
    begin
    //Status:=RtlCreateUserThread(ProcessHandle, nil, false, 0, 0,0, GetProcAddress (GetModuleHandle('dll'),'func') , pchar('param'), @hThread, @ClientID);
    hThread:=thandle(-1);
    OutputDebugString(pchar('LoadLibraryA:'+inttohex(nativeuint(GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA')),8)));
    Status:=RtlCreateUserThread(ProcessHandle, nil, false, 0, 0,0, GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA'), baseaddress , @hThread, @ClientID);
    //@GetThreadInformation:=GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetThreadInformation');
    //GetThreadInformation(hThread,ThreadDynamicCodePolicy,@dwThreadPolicy, sizeof(DWORD));
    //OutputDebugStringA(pchar('ThreadDynamicCodePolicy:'+inttostr(dwThreadPolicy)));
    //ResumeThread(hThread); //if created suspensed
    OutputDebugStringA(pchar('RtlCreateUserThread:'+inttohex(Status,sizeof(status))));
    OutputDebugStringA(pchar('hThread:'+inttostr(hThread)));
    dw:=WaitForSingleObject(hThread,10000);
    OutputDebugString(pchar('WaitForSingleObject:'+inttohex(dw,sizeof(dw))));
    GetExitCodeThread(hThread ,exitcode);
    OutputDebugString(pchar('GetExitCodeThread:'+inttohex(exitcode,sizeof(exitcode))));
    CloseHandle(hThread);
    //VirtualFreeEx(ProcessHandle, baseaddress, Size, MEM_RELEASE);
    NtFreeVirtualMemory (ProcessHandle,@baseaddress ,@size,MEM_RELEASE);
    if Status <>0 then result:=false else result:=true;
    end;

end;

function EjectRTL_DLL(ProcessHandle: longword; hmod:thandle):boolean;
const
ThreadDynamicCodePolicy =2;
type TGetThreadInformation=function(hThread:thandle;
  ThreadInformationClass:dword;
  ThreadInformation:pointer;
  ThreadInformationSize:DWORD):boolean;stdcall;
var
  baseaddress: Pointer=nil;
  Size, BytesWritten, TID: ulong;
  dw:dword;
  Status:integer;
  hThread:thandle;
  ClientID:CLIENT_ID ;
  b:boolean;
  GetThreadInformation:tGetThreadInformation;
  dwThreadPolicy:dword;
  exitcode:dword;
begin
  SetLastError(0);
  OutputDebugString(pchar('*** EjectRTL_DLL ***'));
  OutputDebugString(pchar('ProcessHandle:'+inttostr(ProcessHandle)));
  size:=sizeof(hmod);
{
//size:=align(size,$1000);
  //status:=NtAllocateVirtualMemory(ProcessHandle ,@baseaddress,0,@Size,MEM_COMMIT , PAGE_READWRITE);
  //if status<>0 then
  baseaddress:=nil;
  baseaddress :=VirtualAllocEx(ProcessHandle ,nil,size,MEM_COMMIT or MEM_RESERVE , PAGE_EXECUTE_READWRITE);
  OutputDebugStringA(pchar('VirtualAllocEx:'+inttohex(nativeuint(baseaddress),8)));
  if baseaddress=nil then
    begin
    OutputDebugString(pchar('EjectRTL_DLL, NtAllocateVirtualMemory failed,'+inttohex(status,sizeof(status))));
    raise Exception.Create('EjectRTL_DLL, NtAllocateVirtualMemory failed,'+inttohex(status,sizeof(status)));
    result:=false;
    exit;
    end;

  OutputDebugString(pchar('hmod:'+inttohex(hmod,size)));
  //b:=WriteProcessMemory(ProcessHandle, NewModule, Module, Size, BytesWritten);
  //if b=false
  //because we use hmod as a param of our remote thread, we dont need virtualallocex/baseaddress nor writememory
  Status:=NtWriteVirtualMemory(ProcessHandle, baseaddress, @hmod, sizeof(hmod), @BytesWritten);
  if Status<>0
    then
    begin
    OutputDebugString(pchar('NtWriteVirtualMemory failed,'+inttohex(status,sizeof(status))));
    raise Exception.Create('NtWriteVirtualMemory failed,'+inttohex(status,sizeof(status)));
    result:=false;
    end
    else
    begin
    }
    //Status:=RtlCreateUserThread(ProcessHandle, nil, false, 0, 0,0, GetProcAddress (GetModuleHandle('dll'),'func') , pchar('param'), @hThread, @ClientID);
    hThread:=thandle(-1);
    OutputDebugString(pchar('FreeLibrary:'+inttohex(nativeuint(GetProcAddress(GetModuleHandle('kernel32.dll'), 'FreeLibrary')),8)));
    Status:=RtlCreateUserThread(ProcessHandle, nil, false, 0, 0,0, GetProcAddress(GetModuleHandle('kernel32.dll'), 'FreeLibrary'), pointer(hmod) , @hThread, @ClientID);
    //@GetThreadInformation:=GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetThreadInformation');
    //GetThreadInformation(hThread,ThreadDynamicCodePolicy,@dwThreadPolicy, sizeof(DWORD));
    //OutputDebugStringA(pchar('ThreadDynamicCodePolicy:'+inttostr(dwThreadPolicy)));
    //ResumeThread(hThread); //if created suspensed
    OutputDebugStringA(pchar('RtlCreateUserThread:'+inttohex(Status,sizeof(status))));
    OutputDebugStringA(pchar('hThread:'+inttostr(hThread)));
    dw:=WaitForSingleObject(hThread,10000);
    OutputDebugString(pchar('WaitForSingleObject:'+inttohex(dw,sizeof(dw))));
    GetExitCodeThread(hThread ,exitcode);
    OutputDebugString(pchar('GetExitCodeThread:'+inttohex(exitcode,sizeof(exitcode))));
    CloseHandle(hThread);
    if baseaddress<>nil then
       //VirtualFreeEx(ProcessHandle, baseaddress, Size, MEM_RELEASE);
       NtFreeVirtualMemory (ProcessHandle,@baseaddress ,@size,MEM_RELEASE);
    if Status <>0 then result:=false else result:=true;
    {
    end;
    }
end;


function InjectNT_DLL(ProcessHandle: longword; dll: string):boolean;
var
  baseaddress: Pointer=nil;
  Size, TID: longword;
  BytesWritten:ulong;
  dw:dword;
  Status:integer=0;
  hThread:thandle;
  ClientID:CLIENT_ID ;
  //
  Unknown3,Unknown7: cardinal;
  exitcode:dword;
  ntbuf: NT_THREAD_BUFFER;
  ret:longint;
begin
 OutputDebugString(pchar('*** InjectNT_DLL ***:'+inttostr(ProcessHandle)));
 OutputDebugString(pchar('ProcessHandle:'+inttostr(ProcessHandle)));
 size:=length(dll)+sizeof(char);
  size:=align(size,$1000);
  status:=NtAllocateVirtualMemory(ProcessHandle ,@baseaddress,0,@Size,MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
  //baseaddress :=VirtualAllocEx(ProcessHandle ,nil,size,MEM_COMMIT or MEM_RESERVE , PAGE_EXECUTE_READWRITE);
  //OutputDebugStringA(pchar('VirtualAllocEx:'+inttohex(nativeuint(baseaddress),8)));
  if status<>0 then
  //if baseaddress=nil then
    begin
    result:=false;
    raise Exception.Create('NtAllocateVirtualMemory failed,'+inttohex(status,4));
    exit;
    end;


  Status:=NtWriteVirtualMemory(ProcessHandle, baseaddress, @dll[1], size, @BytesWritten);
  if Status<>0
  //if writeprocessmemory(ProcessHandle,baseaddress,@dll[1],size,@byteswritten)=false
    then
    begin
    result:=false;
    raise Exception.Create('NtWriteVirtualMemory failed,'+inttohex(status,4));
    end
    else
    begin
    //
    //objpfc
    //pointer(TNtCreateThreadEx):=GetProcAddress(LoadLibrary('ntdll.dll'), 'NtCreateThreadEx');
     //NtCreateThreadEx:=GetProcAddress(LoadLibrary('ntdll.dll'), 'NtCreateThreadEx'); //part of untdll

  if (@NtCreateThreadEx <> nil) then
  begin
  ntbuf.Size := SizeOf(NT_THREAD_BUFFER);
  fillchar(Unknown3 ,sizeof(Unknown3 ),0);
  Unknown7 := 0;
  ntbuf.Unknown1 := $10003;
  ntbuf.Unknown2 := $8;
  ntbuf.Unknown3 := @Unknown3;
  ntbuf.Unknown4 := 0;
  ntbuf.Unknown5 := $10004;
  ntbuf.Unknown6 := 4;
  ntbuf.Unknown7 := @Unknown7;
  ntbuf.Unknown8 := 0;
  hThread:=0;
  OutputDebugString(pchar('LoadLibraryA:'+inttohex(nativeuint(GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA')),sizeof(nativeuint))));
  //on x64, replace @ntbuf with nil ...
  ret:=NtCreateThreadEx(@hThread,$1FFFFF, nil, ProcessHandle, GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA'), baseaddress, False, 0, nil, nil, nil);
  end;
  //
  OutputDebugStringA(pchar('NtCreateThreadEx:'+inttohex(ret,sizeof(ret))));
  OutputDebugStringA(pchar('hThread:'+inttostr(hThread)));
    dw:=WaitForSingleObject(hThread,10000);
    OutputDebugString(pchar('WaitForSingleObject:'+inttohex(dw,sizeof(dw))));
    GetExitCodeThread(hThread ,exitcode);
    //inx32 world, exitcode is the base address of our dll
    OutputDebugString(pchar('GetExitCodeThread:'+inttohex(exitcode,sizeof(exitcode))));
    CloseHandle(hThread);
    if baseaddress<>nil then
       //VirtualFreeEx(ProcessHandle, baseaddress, Size, MEM_RELEASE);
       NtFreeVirtualMemory (ProcessHandle,@baseaddress ,@size,MEM_RELEASE);
    if hThread <>0 then result:=true else result:=false;
    end;


end;


{
function InjectNT_CODE(ProcessHandle: longword; EntryPoint: pointer):boolean;
var
  Module, baseaddress: Pointer;
  Size, BytesWritten, TID: longword;
  Status:integer;
  hThread:thandle;
  ClientID:CLIENT_ID ;
  //
  Unknown3, Unknown7: Cardinal;
  ntbuf: NT_THREAD_BUFFER;
begin

  Module := Pointer(GetModuleHandle(nil));
  size:=0;status:=0;
  //VirtualFreeEx(ProcessHandle, Module, 0, MEM_RELEASE);
  status:=NtFreeVirtualMemory(ProcessHandle, @module, @size, MEM_RELEASE);
  if status<>0 then
    begin
    raise Exception.Create('NtFreeVirtualMemory $'+inttohex(integer(module),4)+' failed,'+inttohex(status,4));
    result:=false;
    exit;
    end;

  Size := PImageOptionalHeader(Pointer(integer(Module) + PImageDosHeader(Module)^._lfanew + SizeOf(dword) + SizeOf(TImageFileHeader)))^.SizeOfImage;
  size:=align(size,$1000);
  SetLastError(0);

  //STATUS_INVALID_HANDLE=C0000008
  //STATUS_ACCESS_DENIED=C0000005
  //STATUS_CONFLICTING_ADDRESSES=0xC0000018
  baseaddress:=module;
  status:=NtAllocateVirtualMemory(ProcessHandle ,@baseaddress,0,@Size,MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if status<>0 then
    begin
    result:=false;
    raise Exception.Create('NtAllocateVirtualMemory failed,'+inttohex(status,4));
    exit;
    end;

  Status:=NtWriteVirtualMemory(ProcessHandle, baseaddress, Module, Size, @BytesWritten);
  if Status<>0
    then
    begin
    result:=false;
    raise Exception.Create('NtWriteVirtualMemory failed,'+inttohex(status,4));
    end
    else
    begin
    //
    TNtCreateThreadEx:=GetProcAddress(LoadLibrary('ntdll.dll'), 'NtCreateThreadEx');
  if (@TNtCreateThreadEx <> nil) then
  begin
  ntbuf.Size := SizeOf(NT_THREAD_BUFFER);
  Unknown3 := 0; Unknown7 := 0;
  ntbuf.Unknown1 := $10003;
  ntbuf.Unknown2 := $8;
  ntbuf.Unknown3 := @Unknown3;
  ntbuf.Unknown4 := 0;
  ntbuf.Unknown5 := $10004;
  ntbuf.Unknown6 := 4;
  ntbuf.Unknown7 := @Unknown7;
  ntbuf.Unknown8 := 0;
  hThread:=0;
  TNtCreateThreadEx(@hThread,$1FFFFF, nil, ProcessHandle, EntryPoint, nil, False, 0, 0, 0, @ntbuf);
  end;
  //
    WaitForSingleObject(hThread, INFINITE);
    if hThread <>0 then result:=true else result:=false;
    end;

    //size:=0;
    //NtFreeVirtualMemory(ProcessHandle, @module, @size, MEM_RELEASE);

end;
}

//***************************************************************************************************************
{
function __CreateRemoteThread(hProcess: Cardinal; lpThreadAttributes: Pointer; dwStackSize: Cardinal;
lpStartAddress, lpParameter: Pointer; dwCreationFlags: Cardinal; var lpThreadId: Cardinal): Cardinal;
var
Unknown3, Unknown7, hThread: Cardinal;
ntbuf: NT_THREAD_BUFFER;
begin
Result := 0;

//objfpc
//pointer(__NtCreateThreadEx) := GetProcAddress(LoadLibrary('ntdll.dll'), 'NtCreateThreadEx');
__NtCreateThreadEx := GetProcAddress(LoadLibrary('ntdll.dll'), 'NtCreateThreadEx');
if (@__NtCreateThreadEx <> nil) then
begin
ntbuf.Size := SizeOf(NT_THREAD_BUFFER);
Unknown3 := 0;
Unknown7 := 0;
ntbuf.Unknown1 := $10003;
ntbuf.Unknown2 := $8;
ntbuf.Unknown3 := @Unknown3;
ntbuf.Unknown4 := 0;
ntbuf.Unknown5 := $10004;
ntbuf.Unknown6 := 4;
ntbuf.Unknown7 := @Unknown7;
ntbuf.Unknown8 := 0;

__NtCreateThreadEx(hThread, $1FFFFF, nil, hProcess, lpStartAddress, lpParameter, False, 0, 0, 0, ntbuf);

if (hThread <> 0) then
Result := hThread;
end
else
Result := CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
lpThreadId);
end;
}

function InjectString(hProcess: Cardinal; Text: String): PChar;
var
nBytes: ulong;
begin
Result := VirtualAllocEx(hProcess, nil, Length(Text) + 1, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
if not (WriteProcessMemory(hProcess, Result, PChar(Text), Length(Text) + 1, @nBytes)) then
Result := nil;
end;

function InjectMemory(hProcess: Cardinal; pBuffer: Pointer; dwBufLen: Cardinal): Pointer;
var
nBytes: ulong;
begin
Result := VirtualAllocEx(hProcess, nil, dwBufLen, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if not (WriteProcessMemory(hProcess, Result, pBuffer, dwBufLen, @nBytes)) then
Result := nil;
end;

{
function InjectThread(hProcess: Cardinal; pThreadFunc: Pointer; pThreadParam: Pointer; dwFuncSize,
dwParamSize: Cardinal; Results: Boolean): Cardinal;
var
pThread, pParam: Pointer;
TID: Cardinal;
nBytes:ulong;
begin
pParam := InjectMemory(hProcess, pThreadParam, dwParamSize);
pThread := InjectMemory(hProcess, pThreadFunc, dwFuncSize);
Result := __CreateRemoteThread(hProcess, nil, 0, pThread, pParam, 0, TID);
if Results then
begin
WaitForSingleObject(Result, INFINITE);
ReadProcessMemory(hProcess, pParam, pThreadParam, dwParamSize, @nBytes);
end; 
end;
}

end.
