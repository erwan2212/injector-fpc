unit umain;

{$mode objfpc}{$H+}
//{$mode delphi}{$H+}

interface

uses
  Classes, windows,SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ComCtrls,injection,ntdll;

type

  { TForm1 }

  TForm1 = class(TForm)
    btninject: TButton;
    btnenum: TButton;
    btneject: TButton;
    btnrefresh: TButton;
    RadioButton4: TRadioButton;
    RadioButton5: TRadioButton;
    txtprocess: TComboBox;
    Label1: TLabel;
    Label3: TLabel;
    ListBox1: TListBox;
    RadioButton1: TRadioButton;
    RadioButton2: TRadioButton;
    RadioButton3: TRadioButton;
    StatusBar1: TStatusBar;
    txtdata: TEdit;
    txtdll: TEdit;
    txtpid: TEdit;
    procedure btninjectClick(Sender: TObject);
    procedure btnenumClick(Sender: TObject);
    procedure btnejectClick(Sender: TObject);
    procedure btnrefreshClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure txtprocessExit(Sender: TObject);
    procedure txtprocessSelect(Sender: TObject);
  private

  public

  end;

  //psapi
  type phmodule=^hmodule;
  function EnumProcessModules(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD;var lpcbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';
  function GetModuleFileNameExA(hProcess: HANDLE; hModule: HMODULE; lpFilename: LPSTR; nSize: DWORD): DWORD; stdcall;external 'psapi.dll';
  function EnumProcesses(lpidProcess: LPDWORD; cb: DWORD; var cbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';
  function GetModuleBaseNameA(hProcess: HANDLE; hModule: HMODULE; lpBaseName: LPSTR;nSize: DWORD): DWORD; stdcall;external 'psapi.dll';
  //
  function GetThreadId(thread:thandle):NTSTATUS;stdcall;external 'kernel32.dll';
var
  Form1: TForm1;
  hMemFile:thandle;
  //ps:TDGProcessList ;

implementation

{$R *.lfm}

procedure log(msg:string;level:byte=0);
begin
//do nothing...
end;

function _EnumProc(search:string='';items:tstrings=nil):dword;
var
  cb,cbneeded,cbneeded2:dword;
  count:dword;
  pids,modules:array[0..1023] of dword;
  hProcess:thandle;
  szProcessName:array[0..259] of char;
  username,domain,tmp:string;
begin
result:=0;
   cb:=sizeof(dword)*1024;
   if EnumProcesses (@pids[0],cb,cbneeded) then
      begin
      //writeln(cbneeded div sizeof(dword)); //debug
      for count:=0 to cbneeded div sizeof(dword) - 1 do
          begin
          //beware of 32bit process onto 64bits processes...
          hProcess := OpenProcess( PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
                                   FALSE, pids[count] );
          if hprocess<=0 then log( inttostr(pids[count])+', OpenProcess failed - '+inttostr(getlasterror));
          if hprocess>0 then
          if GetModuleBaseNameA( hProcess, 0, szProcessName,sizeof(szProcessName))<>0 then
             begin
             if search='' then
                begin
                {
                if GetProcessUserAndDomain (pids[count],username,domain)=true
                   then tmp:=domain+'\'+username
                   else tmp:='';
                }
                log(inttostr(pids[count])+ #9+szProcessName+#9+tmp,1 );
                if items<>nil then Items.add(szProcessName);
                end; //if search='' then
             if lowercase(search)=lowercase(strpas(szProcessName) ) then
                begin
                result:=pids[count];
                break;
                end; //if lowercase...
             end// if GetModuleBaseNameA...
             else log( inttostr(pids[count])+', GetModuleBaseNameA failed - '+inttostr(getlasterror));
             closehandle(hProcess);
          end; //for count:=0...
      end//if EnumProcesses...
      else log('EnumProcesses failed, '+inttostr(getlasterror));
end;

function enablepriv(priv:string):boolean;
var
TP, Prev: TTokenPrivileges;
  RetLength: DWORD;
  Token: THandle;
  LUID: TLargeInteger;
begin
result:=false;
try
if OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, Token) then
    begin
    if LookupPrivilegeValue(nil, pchar(priv), LUID) then
    begin
    TP.PrivilegeCount := 1;
    TP.Privileges[0].Luid := LUID;
    TP.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    if not AdjustTokenPrivileges(Token, False, TP, SizeOf(TTokenPrivileges), Prev, RetLength) then RaiseLastWin32Error;
    result:=true;
    end;//LookupPrivilegeValue
    CloseHandle(Token);
    end;//OpenProcessToken
except
on e:exception do raise exception.Create(e.Message );
end;
end;

function EnableDebugPrivilege(const Value: Boolean): Boolean;
const
  SE_DEBUG_NAME = 'SeDebugPrivilege';
var
  hToken: THandle;
  tp,prev: TOKEN_PRIVILEGES;
  d: DWORD;
  ret:boolean;
begin

  Result := False;
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken) then
  begin
    tp.PrivilegeCount := 1;
    LookupPrivilegeValue(nil, SE_DEBUG_NAME, tp.Privileges[0].Luid);
    if Value then
      tp.Privileges[0].Attributes := $00000002
    else
      tp.Privileges[0].Attributes := $80000000;
    d:=0;
    ret:=AdjustTokenPrivileges(hToken, False, tp, SizeOf(TOKEN_PRIVILEGES), prev, d);
    if GetLastError = ERROR_SUCCESS then
    begin
      Result := True;
    end;
    //messageboxa(0,pchar(BoolToStr (ret)+':'+inttostr(getlasterror)),'test',IDYES  );
    CloseHandle(hToken);
  end;
end;



function Proc(dwEntryPoint: Pointer): longword; stdcall;
type msgbox=function(hWnd: HWND; lpText, lpCaption: PAnsiChar; uType: UINT): Integer; stdcall;
var
buffer:pchar;
p:pointer;
func:msgbox;
begin
  {now we are in notepad}
  //LoadLibraryA('kernel32.dll');
  pointer(func):=GetProcAddress(LoadLibraryA('user32.dll'),'messageboxa');
  //p:=VirtualAlloc(buffer,8,MEM_COMMIT,PAGE_READWRITE);
  func(0,pchar('hello from remote process'),pchar('proc'),MB_OK );
  //virtualfree(p,0,MEM_RELEASE);
  Result := 0;
end;

function Proc2(dwEntryPoint: Pointer): longword; stdcall;
var hfile:thandle;
s:string;
written:cardinal;
p:pointer;
begin
  LoadLibrary('kernel32.dll');
  LoadLibrary('user32.dll');
  hFile := CreateFile(pchar('c:\test.txt'), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
  p:=VirtualAlloc(nil,8,MEM_COMMIT,PAGE_READWRITE);
  s:=(inttostr(GetCurrentProcessId )); //'12345678';
  CopyMemory(p,@s[1],length(s));
  WriteFile(hfile,p^,8,written,nil);
  virtualfree(p,0,MEM_RELEASE);
  CloseHandle(hfile);
  Result := 0;
end;

function Proc3(param: Pointer): longword; stdcall;
var
written:cardinal;
p:pchar;
begin
//p:=pchar(param^);
//showmessage(strpas(p));
  LoadLibrary('kernel32.dll');
  LoadLibrary('user32.dll');
  //messageboxa(0,pchar(inttostr(getcurrentprocessid)),'lpcaption',MB_OK );
  //freelibrary(loadlibrary(p));
  freelibrary(loadlibrary('hook.dll'));
  Result := 0;
end;

function setdata(data:string):boolean;
  type tipc=record
  buffer:array [0..255] of char;
  end;
var
ipc:pointer;
mapname:string;
begin

if hMemFile =0 then
begin
//lets create our ipc 'server'
if enablepriv('SeCreateGlobalPrivilege')=true then mapname:='Global\injector' else mapname:='injector';
hMemFile:= CreateFileMapping($FFFFFFFF, nil, PAGE_READWRITE, 0, SizeOf(tipc ), pchar(mapname));
//on the ipc 'client' side, we will use hMemFile  := OpenFileMapping(FILE_MAP_ALL_ACCESS, False, 'injector');
end;

//CreateFileMapping vs OpenFileMapping...

if hMemFile>0 then
begin
OutputDebugString(pchar('CreateFileMapping:'+mapname ));
ipc := MapViewOfFile(hMemFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
if ipc<>nil then
  begin
  fillchar(tipc(ipc^).buffer, sizeof(tipc(ipc^).buffer),0);
  CopyMemory(@tipc(ipc^).buffer[0],@data[1],length(data));
  OutputDebugString('MapViewOfFile done.');
  end;
end;//if hMemFile>0 then
end;

procedure TForm1.btninjectClick(Sender: TObject);
var
PID: longword;
ProcessHandle,ThreadHandle,oldth:thandle;
h:thandle;
i:integer;
oa:TObjectAttributes;
cid:CLIENT_ID ;
access:dword;
p:pchar;
status:integer;
begin

ProcessHandle:=thandle(-1);
if EnableDebugPrivilege(true)=false then
  begin
  showmessage('EnableDebugPrivilege failed');
  exit;
  end;
setlasterror(0);

setdata(txtdata.Text );

pid:=0;
pid:=_EnumProc (txtprocess.Text );
if pid<>0 then txtpid.text:=inttostr(pid);

  if txtpid.Text <>'' then pid:=strtoint(txtpid.Text );
  if pid<>0 then
  begin
    ProcessHandle :=thandle(-1);
    ThreadHandle :=thandle(-1);
    access:=PROCESS_ALL_ACCESS ;
    //access:=PROCESS_CREATE_THREAD or PROCESS_QUERY_INFORMATION or PROCESS_VM_OPERATION or PROCESS_VM_WRITE or PROCESS_VM_READ;
    //ProcessHandle := OpenProcess(access, False, PID);
    //

    InitializeObjectAttributes(oa,nil,0,0,nil);
    cid.UniqueProcess :=pid;
    cid.UniqueThread :=0;
    status:=NtOpenProcess(@ProcessHandle,access,@oa,@cid);
    if status<>0 then begin showmessage('NtOpenProcess failed,'+inttohex(status,4));exit;end;
    //
    if ProcessHandle >0 then
      begin
      try
      if RadioButton1.Checked then
        begin

        //if Inject_RemoteThreadCODE (ProcessHandle, @proc3)=false then showmessage('Inject failed') else  showmessage('Inject ok');
        if InjectNT_RemoteThreadDLL (ProcessHandle, txtdll.text+#0)=false then StatusBar1.SimpleText :=('Inject failed') else  StatusBar1.SimpleText :=('Inject ok');
        end;
      if RadioButton2.Checked then
        begin
        //getmem(p,length(ExtractFilePath(Application.ExeName)+'hook.dll'));
        //p:=pchar(ExtractFilePath(Application.ExeName)+'hook.dll');
        p:='hook.dll';
        //if InjectRTL_CODE(ProcessHandle, @proc,p)=false then showmessage('InjectRTL failed') else showmessage('InjectRTL ok');
        if InjectRTL_dll(ProcessHandle, txtdll.text+#0)=false then StatusBar1.SimpleText :=('InjectRTL failed') else StatusBar1.SimpleText :=('InjectRTL ok');
        end;

      if RadioButton4.Checked then
        begin
        status:=NtGetNextThread(ProcessHandle ,0,MAXIMUM_ALLOWED,0,0,@ThreadHandle);
        if status=0 then
           if injectNT_CTX (ProcessHandle ,ThreadHandle ,txtdll.text+#0)=false then StatusBar1.SimpleText :=('injectctx failed') else StatusBar1.SimpleText :=('injectctx ok');
        //if InjectRTL_DLL(ProcessHandle, 'c:\hook.dll')=false then showmessage('InjectRTL failed') else showmessage('InjectRTL ok');
        //if injectapc (ProcessHandle ,0,txtdll.text+#0) =false then StatusBar1.SimpleText :=('InjectAPC failed') else StatusBar1.SimpleText :=('InjectAPC ok');
        end;

      if RadioButton5.Checked then
        begin
        ThreadHandle:=0; //or -1.
        {
        status:=NtGetNextThread(ProcessHandle,0,MAXIMUM_ALLOWED,0,0,ThreadHandle);
        if status=0 then
          begin
          outputdebugstring(pchar('tid:'+inttostr(GetThreadId(ThreadHandle))));
          if injectAPC_DLL  (ProcessHandle ,ThreadHandle ,txtdll.text+#0)=false then StatusBar1.SimpleText :=('injectAPC failed') else StatusBar1.SimpleText :=('injectAPC ok');
          end;
        }
        //{
        while status=0 do
              begin
              oldth:=ThreadHandle; //zero on first round
              status:=ntGetNextThread(
                   ProcessHandle ,
                   oldth,    //or use ThreadHandle but then leak...
                   MAXIMUM_ALLOWED, //THREAD_ALL_ACCESS THREAD_QUERY_INFORMATION
                   0,
                   0,
                   @ThreadHandle  //newthread
                   );
              closehandle(oldth); //avoid leaking
              if status=0 then
                  begin
                  outputdebugstring(pchar('tid:'+inttostr(GetThreadId(ThreadHandle))));
                  if injectAPC_DLL  (ProcessHandle ,ThreadHandle ,txtdll.text+#0)=false then StatusBar1.SimpleText :=('injectAPC failed') else StatusBar1.SimpleText :=('injectAPC ok');
                  //closehandle(oldth);
                  end;
              end;
             //}
        end;

      if RadioButton3.Checked then
        begin
        //if InjectNT_CODE(ProcessHandle, @proc3)=false then showmessage('InjectNT failed') else showmessage('InjectNT ok');
        if InjectNT_DLL(ProcessHandle, txtdll.text+#0)=false then StatusBar1.SimpleText :=('InjectNT failed') else StatusBar1.SimpleText :=('InjectNT ok');
        end;
      except
      on e:exception do showmessage(e.Message );
      end;
      if ThreadHandle<>thandle(-1) then CloseHandle(ThreadHandle);
      if ProcessHandle<>thandle(-1) then CloseHandle(ProcessHandle);
      end
      else showmessage('NtOpenProcess failed,'+inttostr(getlasterror));
  end
  else showmessage('GetWindowThreadProcessId failed,'+inttostr(getlasterror));
//

closehandle(ProcessHandle );
sleep(100);
btnenumClick (self);
end;

procedure TForm1.btnenumClick(Sender: TObject);
var
hprocess:thandle=0;
 hmods:array[0..1023] of thandle;
 cbneeded,count:dword;
 szModName:array[0..254] of char;
 dummy:string;
begin
ListBox1.Clear ;
if txtpid.text='' then exit;
hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                      false,strtoint(txtpid.text));



EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded);
for count:=0 to (cbneeded div sizeof(thandle))-1 do
    begin
      GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) );
      dummy:=lowercase(strpas(szModName ));
      ListBox1.Items.Add  (dummy+' | '+inttohex(hMods[count],sizeof(thandle)));
    end;
closehandle(hprocess);
end;

procedure TForm1.btnejectClick(Sender: TObject);
var
tmp:string;

ProcessHandle:thandle;
oa:TObjectAttributes;
cid:CLIENT_ID ;
access:dword;
status:integer;
hmod:int64;
begin
if txtpid.text='' then exit;
//
tmp:=ListBox1.Items [ListBox1.ItemIndex];
delete(tmp,1,pos('|',tmp)+1);
hmod:=strtoint64('$'+tmp);
if MessageBoxA(0,pchar('eject 0x'+tmp+'?'),'injector',MB_YESNO )=idno then exit;
//
ProcessHandle :=thandle(-1);
access:=PROCESS_ALL_ACCESS ;
    InitializeObjectAttributes(oa,nil,0,0,nil);
    cid.UniqueProcess :=strtoint(txtpid.text);
    cid.UniqueThread :=0;
    status:=NtOpenProcess(@ProcessHandle,access,@oa,@cid);
    if status<>0 then begin showmessage('NtOpenProcess failed,'+inttohex(status,4));exit;end;

    if EjectRTL_DLL(ProcessHandle ,hmod)=false
       then StatusBar1.SimpleText := ('EjectRTL_DLL failed')
       else StatusBar1.SimpleText :=('EjectRTL_DLL OK');

    closehandle(ProcessHandle );

    btnenumClick (self);

end;

procedure TForm1.btnrefreshClick(Sender: TObject);
begin
  txtprocess.Clear ;
_EnumProc ('',txtprocess.Items );
if txtprocess.Items.Count >0 then
   begin
   txtprocess.ItemIndex :=0;
   txtprocessSelect(self);
   end;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: boolean);
begin
  if hmemfile<>thandle(-1) then closehandle(hmemfile);
end;

procedure TForm1.FormCreate(Sender: TObject);
var
p:pchar;
dw:dword;
s:string;
begin

{$ifdef cpu64}
form1.Caption :='injector x64';
{$else cpu64}
form1.Caption :='injector x86';
{$endif cpu64}

//StatusBar1.SimpleText :='$'+inttohex(nativeuint(Pointer(GetModuleHandle(nil))),4);
dw:=1000;
hMemFile:=0;
txtdll.Text :=ExtractFilepath(Application.ExeName )+'hook.dll';
//p:=pchar(DwordToStr(dw));
//p:=pchar('test');
//showmessage(strpas(p));
btnrefreshClick(self);
end;

procedure TForm1.txtprocessExit(Sender: TObject);
begin

end;

procedure TForm1.txtprocessSelect(Sender: TObject);
begin
  txtpid.text:= inttostr(_EnumProc (txtprocess.text ));
end;




{$ASMMODE intel}
{
procedure loadDll; assembler;
asm
      push $DEADBEEF // EIP
      pushfd
      pushad
      push $DEADBEEF // memory with dll name
      mov eax, $DEADBEEF // loadlibrary address
      call eax
      popad
      popfd
      ret
end;
}

procedure dEnd; assembler;
asm

end;

{
procedure InjectLib(const PID, TID: DWORD; DLL_NAME: PChar);
var
   stub, dllString: Pointer;
  stubLen, oldIP, oldprot, loadLibAddy, ret: DWORD;
  hProcess, hThread: THandle;
  ctx: CONTEXT;
  begin
   stubLen := DWORD(@dEnd) - DWORD(@loadDll);

   loadLibAddy := DWORD(GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA'));

   hProcess := OpenProcess(PROCESS_VM_WRITE or PROCESS_VM_OPERATION, False, PID);

   dllString := VirtualAllocEx(hProcess, nil, (lstrlen(DLL_NAME)+1), MEM_COMMIT, PAGE_READWRITE);
   stub := VirtualAllocEx(hProcess, nil, stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   WriteProcessMemory(hProcess, dllString, DLL_NAME, lstrlen(DLL_NAME), ret);

   hThread := OpenThread(THREAD_GET_CONTEXT or THREAD_SET_CONTEXT or THREAD_SUSPEND_RESUME, false, TID);
   SuspendThread(hThread);

   ZeroMemory(@ctx, sizeof(ctx));

   ctx.ContextFlags := CONTEXT_CONTROL;
   GetThreadContext(hThread, ctx);
   oldIP := ctx.Eip;
   ctx.Eip := DWORD(stub);
   ctx.ContextFlags := CONTEXT_CONTROL;

   VirtualProtect(@loadDll, stubLen, PAGE_EXECUTE_READWRITE, @oldprot);

   CopyMemory(pointer(dword(@loaddll) + 1), @oldIP, 4);
   CopyMemory(pointer(dword(@loaddll) + 8), dllString, 4);
   CopyMemory(pointer(dword(@loaddll) + 13), @loadLibAddy, 4);

   WriteProcessMemory(hProcess, stub, @loaddll, stubLen, ret);

   SetThreadContext(hThread, ctx);

   ResumeThread(hThread);

   Sleep(8000);

   VirtualFreeEx(hProcess, dllString, strlen(DLL_NAME), MEM_DECOMMIT);
   VirtualFreeEx(hProcess, stub, stubLen, MEM_DECOMMIT);
   CloseHandle(hProcess);
   CloseHandle(hThread);
end;
}


end.

