unit ntdll;

interface

uses windows;

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

procedure InitializeObjectAttributes(var p: TObjectAttributes; n:PUNICODE_STRING;
                                          a: ULONG; r: THandle; s: PVOID);    

var
      NtWriteVirtualMemory:function(
      ProcessHandle : HANDLE;
      BaseAddress : PVOID;
      Buffer : PVOID;
      BufferLength : ULONG;
      ReturnLength : PULONG
    ): NTSTATUS; stdcall;

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

implementation

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

function initAPI:boolean;
  var lib:hmodule=0;
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
  NtWriteVirtualMemory:=getProcAddress(lib,'NtWriteVirtualMemory');
  RtlCreateUserThread:=getProcAddress(lib,'RtlCreateUserThread');
  NtOpenProcess:=getProcAddress(lib,'NtOpenProcess');
  NtAllocateVirtualMemory:=getProcAddress(lib,'NtAllocateVirtualMemory');
  NtFreeVirtualMemory:=getProcAddress(lib,'NtFreeVirtualMemory');
  NtCreateThreadEx:=getProcAddress(lib,'NtCreateThreadEx');
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
