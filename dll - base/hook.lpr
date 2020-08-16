library hook;
{$mode delphi}

uses windows  ;

Const
{ DllEntryPoint }
DLL_PROCESS_ATTACH = 1;
DLL_THREAD_ATTACH = 2;
DLL_PROCESS_DETACH = 0;
DLL_THREAD_DETACH = 3;

{
The GetModuleHandle function returns a handle to a mapped module without incrementing its reference count.
However, if this handle is passed to the FreeLibrary function,
the reference count of the mapped module will be decremented.
Therefore, do not pass a handle returned by GetModuleHandle to the FreeLibrary function.
Doing so can cause a DLL module to be unmapped prematurely.
}
function dummy(param:pointer):dword;
begin
OutputDebugString('dummy');
//the below effectively unloads the dll but crashes lsass.exe
//FreeLibraryAndExitThread(GetModuleHandle('hook.dll'), 0);
sleep(1000);
ExitThread(0);

end;

exports dummy;

procedure DLLEntryPoint(dwReason: DWord);
var tid:dword;
  hthread:thandle;
begin
  case dwReason of
    DLL_PROCESS_ATTACH:
      begin
        //DisableThreadLibraryCalls ?
        OutputDebugString ('DLL_PROCESS_ATTACH') ;
        hthread:=CreateThread (nil,$ffff,@dummy,nil,0,tid);
        //dummy(nil);
        WaitForInputIdle (hthread,INFINITE);
        closehandle(hthread );
        //exitthread(0);
        //FreeLibrary(GetModuleHandle(nil));
        exit;
      end;
    DLL_PROCESS_DETACH: OutputDebugString ('DLL_PROCESS_DETACH') ;
    DLL_THREAD_ATTACH:  OutputDebugString ('DLL_THREAD_ATTACH') ;
    DLL_THREAD_DETACH:  OutputDebugString ('DLL_THREAD_DETACH') ;
  end;
end;

procedure DLLTHREADATTACH(dllparam: longint);
begin
DLLEntryPoint(DLL_THREAD_ATTACH);
end;

procedure DLLTHREADDETACH(dllparam: longint);
begin
DLLEntryPoint(DLL_THREAD_DETACH);
end;

procedure DLLPROCESSDETACH(dllparam: longint);
begin
DLLEntryPoint(DLL_PROCESS_DETACH);
end;


begin
OutputDebugString('BEGIN');
{$ifdef fpc}
Dll_Thread_Attach_Hook := @DLLTHREADATTACH;
Dll_Thread_Detach_Hook := @DLLTHREADDETACH;
Dll_Process_Detach_Hook := @DLLPROCESSDETACH;
{$else }
  DLLProc:= @DLLEntryPoint;
{$endif}
DLLEntryPoint(DLL_PROCESS_ATTACH);
end.


 
