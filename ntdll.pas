unit ntdll;

//{$DEFINE syscall}

interface

uses windows,sysutils,base64
  {$IFDEF syscall},debug {$ENDIF}; //,uLkJSON in '..\ikJSON\uLkJSON.pas',variants;

//const OBJ_VALID_PRIVATE_ATTRIBUTES   =$00010000;
//const OBJ_ALL_VALID_ATTRIBUTES = (OBJ_VALID_PRIVATE_ATTRIBUTES or OBJ_VALID_ATTRIBUTES);

const
    SECTION_MAP_EXECUTE{: DWORD} = 8;
    ViewShare = 1;
    ViewUnmap = 2;

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

    Privilege = (
          SeCreateTokenPrivilege = 1,
          SeAssignPrimaryTokenPrivilege = 2,
          SeLockMemoryPrivilege = 3,
          SeIncreaseQuotaPrivilege = 4,
          SeUnsolicitedInputPrivilege = 5,
          SeMachineAccountPrivilege = 6,
          SeTcbPrivilege = 7,
          SeSecurityPrivilege = 8,
          SeTakeOwnershipPrivilege = 9,
          SeLoadDriverPrivilege = 10,
          SeSystemProfilePrivilege = 11,
          SeSystemtimePrivilege = 12,
          SeProfileSingleProcessPrivilege = 13,
          SeIncreaseBasePriorityPrivilege = 14,
          SeCreatePagefilePrivilege = 15,
          SeCreatePermanentPrivilege = 16,
          SeBackupPrivilege = 17,
          SeRestorePrivilege = 18,
          SeShutdownPrivilege = 19,
          SeDebugPrivilege = 20,
          SeAuditPrivilege = 21,
          SeSystemEnvironmentPrivilege = 22,
          SeChangeNotifyPrivilege = 23,
          SeRemoteShutdownPrivilege = 24,
          SeUndockPrivilege = 25,
          SeSyncAgentPrivilege = 26,
          SeEnableDelegationPrivilege = 27,
          SeManageVolumePrivilege = 28,
          SeImpersonatePrivilege = 29,
          SeCreateGlobalPrivilege = 30,
          SeTrustedCredManAccessPrivilege = 31,
          SeRelabelPrivilege = 32,
          SeIncreaseWorkingSetPrivilege = 33,
          SeTimeZonePrivilege = 34,
          SeCreateSymbolicLinkPrivilege = 35
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

  TOSVersionInfoExW = record
         dwOSVersionInfoSize: DWORD;
         dwMajorVersion: DWORD;
         dwMinorVersion: DWORD;
         dwBuildNumber: DWORD;
         dwPlatformId: DWORD;
         szCSDVersion: array[0..127] of WideChar; { Maintenance string for PSS usage }
         wServicePackMajor: Word;
         wServicePackMinor: Word;
         wSuiteMask: Word;
         wProductType: Byte;
         wReserved: byte;
       end;

     SECTION_INHERIT = ViewShare..ViewUnmap;
     
  PUNICODE_STRING = ^UNICODE_STRING;
  UNICODE_STRING = record
    Length: ushort; //2
    MaximumLength: ushort; //2
    {$ifdef CPU64}dummy:dword;{$endif cpu64} //to align to 8 bytes
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
   PNTSTATUS = ^NTSTATUS;
   HANDLE = THANDLE;

   {
    type _TOKEN_INFORMATION_CLASS =
    (TokenPadding0,
    TokenUser,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId, //12
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    // MaxTokenInfoClass should always be the last enum
    MaxTokenInfoClass);
    TOKEN_INFORMATION_CLASS = _TOKEN_INFORMATION_CLASS;
    }

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

   function GetThreadId(Thread:HANDLE): DWORD;stdcall;external 'kernel32.dll';

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

function NT_SUCCESS(status:ntstatus):boolean;

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

    NtClose:function(Handle : HANDLE): NTSTATUS; stdcall;


    NtSuspendThread:function( ThreadHandle:HANDLE;  SuspendCount:PULONG): NTSTATUS; stdcall;
    NtResumeThread:function( hThread : HANDLE; dwResumeCount : PULONG ): NTSTATUS; stdcall;
    NtAlertResumeThread:function( ThreadHandle:HANDLE;  SuspendCount:PULONG): NTSTATUS; stdcall;

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

    NtCreateProcessEx:function(
       ProcessHandle:PHANDLE;
       DesiredAccess:ACCESS_MASK;
       ObjectAttributes: Pointer;
       ParentProcess:THANDLE;
       Flags:ULONG;
       SectionHandle: THANDLE;
       DebugPort: THANDLE;
       ExceptionPort: THANDLE;
       InJob:BOOLEAN
   ): NTSTATUS; stdcall;

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
  Thebuf: Pointer): NTSTATUS; stdcall;

      NtGetContextThread:function(pThread:handle; pContext:PCONTEXT):NTSTATUS; stdcall;
      NtSetContextThread:function(pThread:handle; Context:PCONTEXT):NTSTATUS; stdcall;

  NtCreateSection :function(
          SectionHandle:PHANDLE;
          DesiredAccess:ACCESS_MASK;
          ObjectAttributes:POBJECT_ATTRIBUTES;
          MaximumSize:PLARGEINTEGER;
          SectionPageProtection:ULONG;
          AllocationAttributes:ULONG;
          FileHandle:HANDLE
          ):NTSTATUS; stdcall;

  NtMapViewOfSection:function(
       SectionHandle : HANDLE;
       ProcessHandle : HANDLE;
       BaseAddress : PPVOID;
       ZeroBits : ULONG;
       CommitSize : ULONG;
       SectionOffset : PLARGE_INTEGER;
       ViewSize : PULONG;
       InheritDisposition : SECTION_INHERIT;
       AllocationType : ULONG;
       Protect : ULONG
     ): NTSTATUS; stdcall;

   NtQueueApcThread:function
(ThreadHandle:HANDLE;
 ApcRoutine:pointer; //PIO_APC_ROUTINE;
 ApcRoutineContext:PVOID;        //param1
 ApcStatusBlock:pointer; //PIO_STATUS_BLOCK; //param2
 ApcReserved:ULONG       //param3
 ):NTSTATUS; stdcall;

 //NtQueueApcThreadEx in win10
 //https://repnz.github.io/posts/apc/user-apc/
 // This will force the current thread to execute the special user APC,
		// Although the current thread does not enter alertable state.
        // The APC will execute before the thread returns from kernel mode.

  NtGetNextThread:function(
        ProcessHandle:handle;
        ThreadHandle:handle;
        DesiredAccess:ACCESS_MASK;
        HandleAttributes:ulong;
        Flags:ulong;
        //var NewThreadHandle:thandle
        NewThreadHandle:phandle
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

            RtlAdjustPrivilege:function(
              Privilege:ULONG;
              Enable:BOOLEAN;
              CurrentThread:BOOLEAN;
              Enabled:PBOOLEAN
            ): NTSTATUS; stdcall;

            NtAdjustPrivilegesToken:function(
                TokenHandle : HANDLE;
                DisableAllPrivileges : BOOLEAN;
                NewState : PTOKEN_PRIVILEGES;
                BufferLength : ULONG;
                PreviousState : PTOKEN_PRIVILEGES;
                ReturnLength : PULONG
              ): NTSTATUS; stdcall;

            NtOpenProcessToken:function(
                ProcessHandle : HANDLE;
                DesiredAccess : ACCESS_MASK;
                TokenHandle : PHANDLE
                ): NTSTATUS; stdcall;


implementation

type tsyscall=array [0..10] of byte;



//we could store a table of offset per O.S
//or better, find the offset directly in ntdll hence making it universal
var  SYSCAL_BUF:array [0..10] of byte=(
     $4c,$8b,$d1,  //mov r10, rcx
     $b8, $FF, $00, $00, $00, //byte 4 (ff) is the syscal ID
     $0f, $05,  //syscall
     $c3 );    //ret

     syscalls:array of tsyscall;


{$ifdef fpc}
{$asmmode intel}
{$endif}

procedure log(msg:string);
begin
{$i-}writeln(msg);{$i+}
end;

function NT_SUCCESS(status:ntstatus):boolean;
begin
result:=false;
if status=STATUS_SUCCESS then result:=true;
end;

function getproc(api:string):pointer;
var
id:byte;
begin
{
setlength(syscalls,length(syscalls)+1); //add one item in the array
copymemory(@syscalls[high(syscalls)],@SYSCAL_BUF[0],length(SYSCAL_BUF)); //copy generic syscall
//get the id from the json
syscalls[high(syscalls)][4]:=id; //update syscall id
result:=@syscalls[high(syscalls)]; //return a pointer
}
result:=allocmem(length(SYSCAL_BUF)); //alloc pointer
copymemory(result,@SYSCAL_BUF[0],length(SYSCAL_BUF)); //copy generic syscall
//get the id from the json
tsyscall(result^)[4]:=id; //update syscall id
end;

//https://www.lifewire.com/windows-version-numbers-2625171
function GetWindowsVer:string;
var
  osver:TOSVersionInfoExW ;
  RtlGetVersion:function(var lpVersionInformation: TOSVERSIONINFOEXW): DWORD; stdcall;
begin
//https://docs.microsoft.com/en-us/windows/release-health/release-information
RtlGetVersion:=getProcAddress(loadlibrary('ntdll.dll'),'RtlGetVersion');
//
   RtlGetVersion(osver ) ;
   result:=(inttostr(osver.dwMajorVersion)+'.'+inttostr(osver.dwMinorVersion)+'.'+inttostr(osver.dwBuildNumber) );
if osver.dwMajorVersion =10 then //buildnumber to version
   begin
        case osver.dwBuildNumber of
        10240:result:=result+'-1507'; //ok
        10586:result:=result+'-1511';
        14393:result:=result+'-1607';
        15063:result:=result+'-1703'; //ok
        16299:result:=result+'-1709'; //ok
        17134:result:=result+'-1803'; //OK
        17763:result:=result+'-1809'; //ok
        18362:result:=result+'-1903'; //19h1
        18363:result:=result+'-1909'; //19h2
        18823:result:=result+'-1909'; //insider?
        19041:result:=result+'-2004';
        19042:result:=result+'-20H2';
        19043:result:=result+'-21H1';
        19044:result:=result+'-21H2';
        //20180:result:=result+'-21H1';
        end;
   end;

end;

{
function get_syscall(api,family,version:string):byte;
var
  js,xs:TlkJSONobject;
  xl:TlkJSONlist ;
  ws: TlkJSONstring;
  s: String='';
  i: Integer;
  //
  hFilein:thandle;
  dwread:dword=0;
  dwFileSize:dword;
  buffer:pointer;
begin

//
hFilein := CreateFile(pchar('nt-per-syscall.json'),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
if hFilein=thandle(-1) then exit;
//
dwFileSize := GetFileSize(hFilein,nil)  ;
if dwFileSize = INVALID_FILE_SIZE then
   begin
   buffer := AllocMem(dwFileSize);
   if ReadFile(hFilein,buffer^,dwFileSize,dwRead,nil)=true then s:=strpas(buffer);
   freemem(buffer);
   end;
closehandle(hFilein );
//

  //writeln(s);
// restore object (parse text)
  js := TlkJSON.ParseText(s) as TlkJSONobject;
  //writeln('parent self-type name: ',js.SelfTypeName);

  if not assigned(js) then
    begin
      //writeln('error: xs not assigned!');
      exit;
    end;



  //or 1.04+ syntax
  //writeln(vartostr(js.Field[api].Field[family].Field[version].Value));
  result:=js.Field[api].Field[family].Field[version].Value;

//
  //readln;
  js.Free;
end;
}

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

{$IFDEF syscall}
function getsyscall(id:byte):pointer;
var
oldprotect:dword;
begin
result:=allocmem(length(SYSCAL_BUF)); //alloc pointer
VirtualProtectEx (GetCurrentProcess ,result,sizeof(SYSCAL_BUF),PAGE_EXECUTE_READWRITE ,@oldprotect);
copymemory(result,@SYSCAL_BUF[0],length(SYSCAL_BUF)); //copy generic syscall
tsyscall(result^)[4]:=id; //update syscall id
end;

function GetProcAddress_Syscall(hModule:HINST; Base64lpProcName:string):FARPROC;
var
procname:string='';
ssn:nativeuint=0;
begin
procname:=DecodeStringBase64(Base64lpProcName);
ssn := RetrieveSyscall( GetProcAddress( hModule, pchar(procname) ) );
outputdebugstring(pchar(procname+':'+procname+' SSN:'+inttohex(ssn,8)));
result:=getsyscall(byte(ssn));
end;

function initapi_syscall:boolean;
var
     h1:pvoid;
     lib:hmodule=0;
begin

  h1:=AddVectoredExceptionHandler(1, LPTOP_LEVEL_EXCEPTION_FILTER(@OneShotHardwareBreakpointHandler));


  result:=false;
    try
    //lib:=0;
    if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
        {$IFDEF win64}lib:=GetModuleHandleA( 'NTDLL.dll' );;{$endif}
        {$IFDEF win32}lib:=GetModuleHandleA( 'NTDLL.dll' );{$endif}
    if lib<=0 then
      begin
      log('could not loadlibrary ntdll.dll');
      exit;
      end;
    //syscall !!!!
    //SYSCAL_BUF [4]:=$FF;
    //VirtualProtectEx (GetCurrentProcess ,@SYSCAL_BUF,sizeof(SYSCAL_BUF),PAGE_EXECUTE_READWRITE ,@oldprotect);
    //NtReadVirtualMemory:=@SYSCAL_BUF;
    NtReadVirtualMemory:=GetProcAddress_syscall(lib,'TnRSZWFkVmlydHVhbE1lbW9yeQ==');
    NtWriteVirtualMemory:=GetProcAddress_syscall(lib,'TnRXcml0ZVZpcnR1YWxNZW1vcnk=');
    NtOpenProcess:=GetProcAddress_syscall(lib,'TnRPcGVuUHJvY2Vzcw==');
    NtAllocateVirtualMemory:=GetProcAddress_syscall(lib,'TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=');
    NtFreeVirtualMemory:=GetProcAddress_syscall(lib,'TnRGcmVlVmlydHVhbE1lbW9yeQ==');
    NtProtectVirtualMemory:=GetProcAddress_syscall(lib,'TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==');
    NtCreateProcessEx:=GetProcAddress_syscall(lib,'TnRDcmVhdGVQcm9jZXNzRXg=');
    NtCreateThreadEx:=GetProcAddress_syscall(lib,'TnRDcmVhdGVUaHJlYWRFeA==');
    NtGetNextThread:=GetProcAddress_syscall(lib,'TnRHZXROZXh0VGhyZWFk');
    NtQueryObject:=GetProcAddress_syscall(lib,'TnRRdWVyeU9iamVjdA==');
    NtQuerySystemInformation:=GetProcAddress_syscall(lib,'TnRRdWVyeVN5c3RlbUluZm9ybWF0aW9u');
    NtDuplicateObject:=GetProcAddress_syscall(lib,'TnREdXBsaWNhdGVPYmplY3Q=');
    NtQueueApcThread:=GetProcAddress_syscall(lib,'TnRRdWV1ZUFwY1RocmVhZA==');
    NtSuspendThread:=GetProcAddress_syscall(lib,'TnRTdXNwZW5kVGhyZWFk');
    NtAlertResumeThread:=GetProcAddress_syscall(lib,'TnRBbGVydFJlc3VtZVRocmVhZA==');
    NtResumeThread:=GetProcAddress_syscall(lib,'TnRSZXN1bWVUaHJlYWQ=');
    NtCreateSection:=GetProcAddress_syscall(lib,'TnRDcmVhdGVTZWN0aW9u');
    NtMapViewOfSection:=GetProcAddress_syscall(lib,'TnRNYXBWaWV3T2ZTZWN0aW9u');
    NtClose:=GetProcAddress_syscall(lib,'TnRDbG9zZQ==');
    NtGetContextThread:=GetProcAddress_syscall(lib,'TnRHZXRDb250ZXh0VGhyZWFk');
    NtSetContextThread:=GetProcAddress_syscall(lib,'TnRTZXRDb250ZXh0VGhyZWFk');
    NtAdjustPrivilegesToken:=GetProcAddress_syscall(lib,'TnRBZGp1c3RQcml2aWxlZ2VzVG9rZW4=');
    NtOpenProcessToken:=GetProcAddress_syscall(lib,'TnRPcGVuUHJvY2Vzc1Rva2Vu=');
    RtlAdjustPrivilege:=GetProcAddress_syscall(lib,'UnRsQWRqdXN0UHJpdmlsZWdl');
    RtlCreateUserThread:=GetProcAddress_syscall(lib,'UnRsQ3JlYXRlVXNlclRocmVhZA==');
    result:=true;
    except
    //on e:exception do writeln('init error:'+e.message);
       log('init error');
    end;

  RemoveVectoredExceptionHandler(h1);

end;



{$ENDIF}


function GetProcAddress_Base64(hModule:HINST; Base64lpProcName:string):FARPROC;
begin
  result:=GetProcAddress (hmodule,pchar(DecodeStringBase64(Base64lpProcName)));
end;

function initAPI:boolean;
  var
  lib:hmodule=0;
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
    log('could not loadlibrary ntdll.dll');
    exit;
    end;
  //syscall !!!!
  //SYSCAL_BUF [4]:=$FF;
  //VirtualProtectEx (GetCurrentProcess ,@SYSCAL_BUF,sizeof(SYSCAL_BUF),PAGE_EXECUTE_READWRITE ,@oldprotect);
  //NtReadVirtualMemory:=@SYSCAL_BUF;
  NtReadVirtualMemory:=GetProcAddress_Base64(lib,'TnRSZWFkVmlydHVhbE1lbW9yeQ==');
  NtWriteVirtualMemory:=GetProcAddress_Base64(lib,'TnRXcml0ZVZpcnR1YWxNZW1vcnk=');
  NtOpenProcess:=GetProcAddress_Base64(lib,'TnRPcGVuUHJvY2Vzcw==');
  NtAllocateVirtualMemory:=GetProcAddress_Base64(lib,'TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=');
  NtFreeVirtualMemory:=GetProcAddress_Base64(lib,'TnRGcmVlVmlydHVhbE1lbW9yeQ==');
  NtProtectVirtualMemory:=GetProcAddress_Base64(lib,'TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==');
  NtCreateProcessEx:=GetProcAddress_Base64(lib,'TnRDcmVhdGVQcm9jZXNzRXg=');
  NtCreateThreadEx:=GetProcAddress_Base64(lib,'TnRDcmVhdGVUaHJlYWRFeA==');
  NtGetNextThread:=GetProcAddress_Base64(lib,'TnRHZXROZXh0VGhyZWFk');
  NtQueryObject:=GetProcAddress_Base64(lib,'TnRRdWVyeU9iamVjdA==');
  NtQuerySystemInformation:=GetProcAddress_Base64(lib,'TnRRdWVyeVN5c3RlbUluZm9ybWF0aW9u');
  NtDuplicateObject:=GetProcAddress_Base64(lib,'TnREdXBsaWNhdGVPYmplY3Q=');
  NtQueueApcThread:=GetProcAddress_Base64(lib,'TnRRdWV1ZUFwY1RocmVhZA==');
  NtSuspendThread:=GetProcAddress_Base64(lib,'TnRTdXNwZW5kVGhyZWFk');
  NtAlertResumeThread:=GetProcAddress_Base64(lib,'TnRBbGVydFJlc3VtZVRocmVhZA==');
  NtResumeThread:=GetProcAddress_Base64(lib,'TnRSZXN1bWVUaHJlYWQ=');
  NtCreateSection:=GetProcAddress_Base64(lib,'TnRDcmVhdGVTZWN0aW9u');
  NtMapViewOfSection:=GetProcAddress_Base64(lib,'TnRNYXBWaWV3T2ZTZWN0aW9u');
  NtClose:=GetProcAddress_Base64(lib,'TnRDbG9zZQ==');
  NtGetContextThread:=GetProcAddress_Base64(lib,'TnRHZXRDb250ZXh0VGhyZWFk');
  NtSetContextThread:=GetProcAddress_Base64(lib,'TnRTZXRDb250ZXh0VGhyZWFk');
  NtAdjustPrivilegesToken:=GetProcAddress_Base64(lib,'TnRBZGp1c3RQcml2aWxlZ2VzVG9rZW4=');
  NtOpenProcessToken:=GetProcAddress_Base64(lib,'TnRPcGVuUHJvY2Vzc1Rva2Vu=');
  RtlAdjustPrivilege:=GetProcAddress_Base64(lib,'UnRsQWRqdXN0UHJpdmlsZWdl');
  RtlCreateUserThread:=GetProcAddress_Base64(lib,'UnRsQ3JlYXRlVXNlclRocmVhZA=='); //not a syscall but a wrapper to NtCreateThreadEx
  result:=true;
  except
  //on e:exception do writeln('init error:'+e.message);
     log('init error');
  end;
  //log('init:'+BoolToStr (result,'true','false'));
  end;

initialization
{$IFDEF syscall}initapi_syscall; {$ENDIF};
{$IFNDEF syscall}initapi; {$ENDIF};


end.
