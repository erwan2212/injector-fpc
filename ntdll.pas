unit ntdll;

interface

uses windows;


  type SYSTEM_INFORMATION_CLASS = (SystemBasicInformation,SystemProcessorInformation,SystemPerformanceInformation,
    SystemTimeOfDayInformation,SystemNotImplemented1,SystemProcessesAndThreadsInformation,
    SystemCallCounts,SystemConfigurationInformation,SystemProcessorTimes,
    SystemGlobalFlag,SystemNotImplemented2,SystemModuleInformation,
    SystemLockInformation,SystemNotImplemented3,SystemNotImplemented4,
    SystemNotImplemented5,SystemHandleInformation,SystemObjectInformation,
    SystemPagefileInformation,SystemInstructionEmulationCounts,SystemInvalidInfoClass1,
    SystemCacheInformation,SystemPoolTagInformation,SystemProcessorStatistics,
    SystemDpcInformation,SystemNotImplemented6,SystemLoadImage,SystemUnloadImage,
    SystemTimeAdjustment,SystemNotImplemented7,SystemNotImplemented8,SystemNotImplemented9,
    SystemCrashDumpInformation,SystemExceptionInformation,SystemCrashDumpStateInformation,SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,SystemRegistryQuotaInformation,
    SystemLoadAndCallImage,SystemPrioritySeparation,SystemNotImplemented10,SystemNotImplemented11,
    SystemInvalidInfoClass2,SystemInvalidInfoClass3,SystemTimeZoneInformation,SystemLookasideInformation,
    SystemSetTimeSlipEvent,SystemCreateSession,SystemDeleteSession,SystemInvalidInfoClass4,
    SystemRangeStartInformation,SystemVerifierInformation,SystemAddVerifier,SystemSessionProcessesInformation
    );


  type
    _CLIENT_ID = record
       UniqueProcess: uint64; //tHANDLE;
       UniqueThread: thandle; //tHANDLE;
     end;
     CLIENT_ID = _CLIENT_ID;
     PCLIENT_ID = ^CLIENT_ID;
     TClientID = CLIENT_ID;
     PClientID = ^TClientID;
     
  PUNICODE_STRING = ^UNICODE_STRING;
  UNICODE_STRING = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

PNT_THREAD_BUFFER = ^NT_THREAD_BUFFER;
NT_THREAD_BUFFER = record
Size,Unknown1,Unknown2: SIZE_T ;
Unknown3: PULONG ;
Unknown4, Unknown5, Unknown6: SIZE_T ;
Unknown7: PULONG ;
Unknown8: SIZE_T ;
end ;

  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;
  OBJECT_ATTRIBUTES = record
    Length: DWORD;
    RootDirectory: thandle;
    ObjectName: PUNICODE_STRING;
    Attributes: DWORD;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;
  TObjectAttributes =OBJECT_ATTRIBUTES;
  
   PVOID = pointer;
   PPVOID = ^PVOID;
   NTSTATUS = ULONG;
   HANDLE = THANDLE;

   type
   OBJECT_INFORMATION_CLASS = (ObjectBasicInformation,ObjectNameInformation,ObjectTypeInformation,ObjectAllTypesInformation,ObjectHandleInformation );

   _OBJECT_BASIC_INFORMATION = record // Information Class 0
    Attributes: ULONG;
    GrantedAccess: ACCESS_MASK;
    HandleCount: ULONG;
    PointerCount: ULONG;
    PagedPoolUsage: ULONG;
    NonPagedPoolUsage: ULONG;
    Reserved: array[0..2] of ULONG;
    NameInformationLength: ULONG;
    TypeInformationLength: ULONG;
    SecurityDescriptorLength: ULONG;
    CreateTime: LARGE_INTEGER;
  end;
  OBJECT_BASIC_INFORMATION = _OBJECT_BASIC_INFORMATION;
  POBJECT_BASIC_INFORMATION = ^OBJECT_BASIC_INFORMATION;
  TObjectBasicInformation = OBJECT_BASIC_INFORMATION;

  OBJECT_TYPE_INFORMATION = record
    Name: UNICODE_STRING;
    ObjectCount: ULONG;
    HandleCount: ULONG;
    Reserved1: array[0..3] of ULONG;
    PeakObjectCount: ULONG;
    PeakHandleCount: ULONG;
    Reserved2: array[0..3] of ULONG;
    InvalidAttributes: ULONG;
    GenericMapping: GENERIC_MAPPING;
    ValidAccess: ULONG;
    Unknown: UCHAR;
    MaintainHandleDatabase: ByteBool;
    Reserved3: array[0..1] of UCHAR;
    PoolType: Byte;
    PagedPoolUsage: ULONG;
    NonPagedPoolUsage: ULONG;
  end;
  POBJECT_TYPE_INFORMATION = ^OBJECT_TYPE_INFORMATION;

  //https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm
  SYSTEM_HANDLE= record
  uIdProcess:ushort;  //2              0
  CreatorBackTraceIndex:ushort; //2    2
  ObjectType:uchar;            //1    4
  Flags     :uchar;            //1    5
  Handle    :ushort;            //2    6
  pObject   :pvoid;         //4    8
  GrantedAccess:ACCESS_MASK; //4     12
  end;                             //16
   PSYSTEM_HANDLE      = ^SYSTEM_HANDLE;
   SYSTEM_HANDLE_ARRAY = Array[0..0] of SYSTEM_HANDLE;
   PSYSTEM_HANDLE_ARRAY= ^SYSTEM_HANDLE_ARRAY;

   SYSTEM_HANDLE_INFORMATION=packed record
     uCount:qword;
     //dummy:dword;
     Handles:SYSTEM_HANDLE_ARRAY;
   end;
   PSYSTEM_HANDLE_INFORMATION=^SYSTEM_HANDLE_INFORMATION;

   {
   function VirtualFreeEx
    (hProcess: THandle;
    lpAddress: Pointer;
    dwSize, dwFreeType: DWORD): cardinal;
    stdcall;external 'kernel32.dll';
   }

   //->dynamic
   {
      function  RtlCreateUserThread(
      hProcess : THANDLE;
      SecurityDescriptor : PSECURITY_DESCRIPTOR;
      CreateSuspended : BOOLEAN;
      StackZeroBits : ULONG;
      StackReserve : SIZE_T;
      StackCommit : SIZE_T;
      lpStartAddress : pointer;
      lpParameter : pointer;
      phThread : PHANDLE;
      ClientId : PCLIENT_ID
    ): NTSTATUS; stdcall; external 'ntdll.dll';
    }

          {
    function NtCreateThreadEx (
    var hThread: Cardinal;
    DesiredAccess: Cardinal;
    lpThreadAttribtes: Pointer;
    hProcess: Cardinal;
    lpStartAddress, lpParameter: Pointer;
    CreateSuspended: Boolean;
    dwStackZeroBits, SizeOfStackCommit, SizeOfStackReserve: Cardinal;
    var Thebuf: NT_THREAD_BUFFER):
    Cardinal; stdcall; external 'ntdll.dll';
    }

    //->dynamic
    {
    function NtCreateThreadEx(
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
  Thebuf: Pointer): HRESULT; stdcall; external 'ntdll.dll';
  }
    //->dynamic
    {
    function  NtWriteVirtualMemory(
      ProcessHandle : HANDLE;
      BaseAddress : PVOID;
      Buffer : PVOID;
      BufferLength : ULONG;
      ReturnLength : PULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';
    }

     {//->dynamic
     function  NtAllocateVirtualMemory(
      ProcessHandle : HANDLE;
      BaseAddress : PPVOID;
      ZeroBits : ULONG;
      AllocationSize : PULONG;
      AllocationType : ULONG;
      Protect : ULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';
     }

      {//->dynamic
    function NtFreeVirtualMemory(
    hProcess: Cardinal;
    lpStartAddress: ppvoid;
    AllocationSize : PULONG;
    AllocationType : ULONG):
    Cardinal; stdcall; external 'ntdll.dll';
    }

    {//->dynamic
    function  NtOpenProcess(
      ProcessHandle : PHANDLE;
      DesiredAccess : ACCESS_MASK;
      ObjectAttributes : POBJECT_ATTRIBUTES;
      ClientId : PCLIENT_ID
    ): NTSTATUS; stdcall; external 'ntdll.dll';
    }

    {
    function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwThreadId: DWORD): DWORD;
    stdcall; external 'kernel32.dll';
    }

const
 THREAD_GET_CONTEXT = $0008;
 THREAD_SET_CONTEXT = $0010;
 THREAD_SUSPEND_RESUME = $0002;
 //
 STATUS_SUCCESS               = ntstatus($00000000);
    STATUS_BUFFER_OVERFLOW        = ntstatus($80000005);
    STATUS_INFO_LENGTH_MISMATCH   = ntstatus($C0000004);
    DefaulBUFFERSIZE              = $100000;

procedure InitializeObjectAttributes(var p: TObjectAttributes; n:PUNICODE_STRING;
                                          a: ULONG; r: THandle; s: PVOID);
function GetObjectInfo(hObject:thandle; objInfoClass:OBJECT_INFORMATION_CLASS):string;

var
NtReadVirtualMemory:function(
  ProcessHandle:HANDLE; //IN HANDLE
  BaseAddress:PVOID; //IN PVOID
  Buffer:PVOID; //OUT PVOID
  NumberOfBytesToRead:ULONG; //IN ULONG
  NumberOfBytesReaded:PULONG): NTSTATUS; stdcall; //OUT PULONG

      NtWriteVirtualMemory:function(
      ProcessHandle : HANDLE;
      BaseAddress : PVOID;
      Buffer : PVOID;
      BufferLength : ULONG;
      ReturnLength : PULONG): NTSTATUS; stdcall;

      RtlCreateUserThread:function(
      hProcess : THANDLE;
      SecurityDescriptor : PSECURITY_DESCRIPTOR;
      CreateSuspended : BOOLEAN;
      StackZeroBits : ULONG;
      StackReserve : SIZE_T;
      StackCommit : SIZE_T;
      lpStartAddress : pointer;
      lpParameter : pointer;
      phThread : PHANDLE;
      ClientId : PCLIENT_ID
    ): NTSTATUS; stdcall;

      NtOpenProcess:function(
      ProcessHandle : PHANDLE;
      DesiredAccess : ACCESS_MASK;
      ObjectAttributes : POBJECT_ATTRIBUTES;
      ClientId : PCLIENT_ID
    ): NTSTATUS; stdcall;

      NtAllocateVirtualMemory:function(
      ProcessHandle : HANDLE;
      BaseAddress : PPVOID;
      ZeroBits : ULONG;
      AllocationSize : PULONG;
      AllocationType : ULONG;
      Protect : ULONG
    ): NTSTATUS; stdcall;

     NtFreeVirtualMemory:function(
    hProcess: Cardinal;
    lpStartAddress: ppvoid;
    AllocationSize : PULONG;
    AllocationType : ULONG):
    Cardinal; stdcall;

    NtCreateThreadEx:function(
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

  NtGetNextThread:function(
        ProcessHandle:thandle;
        ThreadHandle:thandle;
        DesiredAccess:ACCESS_MASK;
        HandleAttributes:ulong;
        Flags:ulong;
        var NewThreadHandle:thandle
       ):NTSTATUS;stdcall;

  NtQueryObject:function(ObjectHandle: THandle;
    ObjectInformationClass: OBJECT_INFORMATION_CLASS;  //OBJECT_INFORMATION_CLASS  //dword
    ObjectInformation: PVOID;
    ObjectInformationLength: ULONG;
    ReturnLength: PULONG): NTSTATUS; stdcall;

    ntquerysysteminformation:function(systeminformationclass:system_information_class;
      systeminformation:pvoid;
      systeminformationlength:ulong;
      returnlength:pulong): ntstatus; stdcall;

      NtDuplicateObject:function(
            SourceProcessHandle : HANDLE;
            SourceHandle : HANDLE;
            TargetProcessHandle : HANDLE;
            TargetHandle : PHANDLE;
            DesiredAccess : ACCESS_MASK;
            Attributes : ULONG;
            Options : ULONG
          ): NTSTATUS; stdcall;

            NtProtectVirtualMemory:function(
              ProcessHandle : HANDLE;
              BaseAddress : PPVOID;
              ProtectSize : PULONG;
              NewProtect : ULONG;
              OldProtect : PULONG
            ): NTSTATUS; stdcall;


implementation

//17h is for win8.1
//we could store a table of offset per O.S
//or better, find the offset directly in ntdll hence making it universal
var  NtAllocateVirtualMemory_BUF:array [0..10] of byte=(
     $4c,$8b,$d1,  //mov r10, rcx
     $b8, $17, $00, $00, $00, //mov eax, 17h //for win 8.1
     $0f, $05,  //syscall
     $c3 );    //ret

var  NtReadVirtualMemory_BUF:array [0..10] of byte=(
     $4c,$8b,$d1,  //mov r10, rcx
     $b8, $3f, $00, $00, $00, //mov eax, 3Eh //for win8.1  //3f for win10
     $0f, $05,  //syscall
     $c3 );    //ret

var  NtOpenProcess_BUF:array [0..10] of byte=(
     $4c,$8b,$d1,  //mov r10, rcx
     $b8, $26, $00, $00, $00, //mov eax, 26h //for win10
     $0f, $05,  //syscall
     $c3 );    //ret

{$ifdef fpc}
{$asmmode intel}
{$endif}

//see
//https://github.com/outflanknl/Dumpert
//https://j00ru.vexillium.org/syscalls/nt/64/
//fpc will add push   rbp & mov    rbp,rsp which I believe messes it up :(
function NtAllocateVirtualMemory_SYS(
      ProcessHandle : HANDLE;
      BaseAddress : PPVOID;
      ZeroBits : ULONG;
      AllocationSize : PULONG;
      AllocationType : ULONG;
      Protect : ULONG): NTSTATUS; stdcall;
asm
        mov r10, rcx
        //mov eax, ds:[7FFE026Ch]
        //cmp eax, 10
        //je win10
        @@win81:
        mov eax, 17h  //syscall is different on each windows version
	syscall
	ret
end;

procedure InitializeObjectAttributes(var p: TObjectAttributes; n:PUNICODE_STRING;
                                          a: ULONG; r: THandle; s: PVOID);
begin
  p.Length := SizeOf(OBJECT_ATTRIBUTES);
  p.RootDirectory := r;
  p.Attributes := a;
  p.ObjectName := n;
  p.SecurityDescriptor := s;
  p.SecurityQualityOfService := nil;
end;

function GetObjectInfo(hObject:thandle; objInfoClass:OBJECT_INFORMATION_CLASS):string;
var
 pObjectInfo:pointer=nil; //POBJECT_NAME_INFORMATION;
 HDummy     :THandle=thandle(-1);
 dwSize     :DWORD=0;
 _result:LPWSTR;
begin
  result:='';
  //dwSize      := sizeof(OBJECT_NAME_INFORMATION);
  dwsize:=$1000;
  //if objInfoClass=ObjectNameInformation then dwsize:= sizeof(OBJECT_NAME_INFORMATION);
  //if objInfoClass=ObjectTypeInformation then dwsize:= sizeof(OBJECT_TYPE_INFORMATION);
  pObjectInfo := AllocMem(dwSize);
  HDummy      := NTQueryObject(hObject, objInfoClass, pObjectInfo,dwsize, @dwSize);

  {
  if((HDummy = STATUS_BUFFER_OVERFLOW) or (HDummy = STATUS_INFO_LENGTH_MISMATCH)) then
    begin
   FreeMem(pObjectInfo);
   pObjectInfo := AllocMem(dwSize);
   HDummy      := NTQueryObject(hObject, objInfoClass, pObjectInfo,dwSize, @dwSize);
  end;
  }

  if (HDummy >= STATUS_SUCCESS) and (pObjectInfo<>nil) then //(pObjectInfo^.Buffer <> nil) then
  begin
   {
   _Result := AllocMem(pObjectInfo^.Length + sizeof(WCHAR));
   CopyMemory(_result, pObjectInfo^.Buffer, pObjectInfo^.Length);
   result:=string(_result);
   if _result<>nil then freemem(_result);
   }
    if objInfoClass=ObjectNameInformation then result:= string(UNICODE_STRING(pObjectInfo^).Buffer);
    if objInfoClass=ObjectTypeInformation then result:= string(OBJECT_TYPE_INFORMATION(pObjectInfo^).Name.Buffer );
  end;

  //if hdummy<>STATUS_SUCCESS then writeln(inttohex(hdummy,sizeof(hdummy)));;
  //C0000008 STATUS_INVALID_PARAMETER

  if pobjectinfo<>nil then FreeMem(pObjectInfo);
end;

function initAPI:boolean;
  var
  lib:hmodule=0;
  oldprotect:dword;
  begin
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('ntdll.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('ntdll.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary ntdll.dll');
    exit;
    end;
  //syscall !!!!
  //VirtualProtectEx (GetCurrentProcess ,@NtReadVirtualMemory_BUF,sizeof(NtReadVirtualMemory_BUF),PAGE_EXECUTE_READWRITE ,@oldprotect);
  //NtReadVirtualMemory:=@NtReadVirtualMemory_BUF;
  NtReadVirtualMemory:=getProcAddress(lib,'NtReadVirtualMemory');
  NtWriteVirtualMemory:=getProcAddress(lib,'NtWriteVirtualMemory');
  RtlCreateUserThread:=getProcAddress(lib,'RtlCreateUserThread');
  //syscall !!!!
  //VirtualProtectEx (GetCurrentProcess ,@NtOpenProcess_BUF,sizeof(NtOpenProcess_BUF),PAGE_EXECUTE_READWRITE ,@oldprotect);
  //NtOpenProcess:=@NtOpenProcess_BUF ;
  NtOpenProcess:=getProcAddress(lib,'NtOpenProcess');
  //syscall !!!!
  //VirtualProtectEx (GetCurrentProcess ,@NtAllocateVirtualMemory_BUF,sizeof(NtAllocateVirtualMemory_BUF),PAGE_EXECUTE_READWRITE ,@oldprotect);
  //NtAllocateVirtualMemory:=@NtAllocateVirtualMemory_BUF;
  NtAllocateVirtualMemory:=getProcAddress(lib,'NtAllocateVirtualMemory');
  NtFreeVirtualMemory:=getProcAddress(lib,'NtFreeVirtualMemory');
  NtProtectVirtualMemory:=getProcAddress(lib,'NtProtectVirtualMemory');
  NtCreateThreadEx:=getProcAddress(lib,'NtCreateThreadEx');
  NtGetNextThread:=getProcAddress(lib,'NtGetNextThread');
  NtQueryObject:=getProcAddress(lib,'NtQueryObject');
  NtQuerySystemInformation:=getProcAddress(lib,'NtQuerySystemInformation');
  NtDuplicateObject:=getProcAddress(lib,'NtDuplicateObject');
  result:=true;
  except
  //on e:exception do writeln('init error:'+e.message);
     writeln('init error');
  end;
  //log('init:'+BoolToStr (result,'true','false'));
  end;

initialization
initAPI ;

end.
