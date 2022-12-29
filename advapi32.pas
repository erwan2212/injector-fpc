unit advapi32;

{$mode delphi}

interface

uses
  windows,sysutils;

var

OpenProcessToken:function(ProcessHandle: THandle; DesiredAccess: DWORD; var TokenHandle: THandle): BOOL;
AdjustTokenPrivileges:function(TokenHandle: THandle; DisableAllPrivileges: BOOL; const NewState: TTokenPrivileges; BufferLength: DWORD;
                               var PreviousState: TTokenPrivileges; var ReturnLength: DWORD): BOOL;
LookupPrivilegeValue:function(lpSystemName, lpName: PChar; var lpLuid: TLargeInteger): BOOL;

//
function EnableDebugPrivilege(const Value: Boolean): Boolean;
function enablepriv(priv:string):boolean;

implementation

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
      {$IFDEF win64}lib:=loadlibrary('advapi32.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('advapi32.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary advapi32.dll');
    exit;
    end;
  OpenProcessToken:=getProcAddress(lib,'OpenProcessToken');
  AdjustTokenPrivileges:=getProcAddress(lib,'AdjustTokenPrivileges');
  LookupPrivilegeValue:=getProcAddress(lib,'LookupPrivilegeValueA');
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

