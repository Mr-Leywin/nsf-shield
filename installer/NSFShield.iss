; NSF Shield setup package (Inno Setup 6.7+). Built by build.ps1, not directly:
;   ISCC /DAppVersion=1.0.0 /DSourceDir=...\build\package\NSF Shield /DOutDir=...\dist /DIconFile=...\build\app.ico
;        /DTouchDate=YYYY-MM-DD /DTouchTime=HH:MM [/DSIGN /Snsfsign=...] installer\NSFShield.iss
;
; - Installs only on 64-bit Windows 10/11, with administrator rights, to Program Files\NSF Shield (protected install:
;   the background service and "Start with Windows" are only available here).
; - On upgrade the data\ folder (settings, profiles, log) is kept; before files are replaced, the old version's
;   --prepare-upgrade command stops the app, the engines (goodbyedpi, winws, ciadpi) and the service of this folder – only
;   when the folder is verified as protected by the NEW program of this package, run from the setup's own temporary
;   folder (NSFShield.exe --check-install-dir: physical path, no junction/symbolic link, owner and write permissions of the
;   folder, its program, the used subfolders and every parent; the Program Files prefix alone proves nothing). An unsafe or
;   unreadable target stops the setup before anything is installed or run. Setup then makes sure itself: the service and
;   the processes of this folder are matched by the physical paths of the allowed executables (Win32 API, the same handle
;   reads the path and closes the process; no script host), and the WinDivert drivers loaded from this folder are unloaded
;   (stop only, entries are kept). Service states are read numerically through the SCM API (not found / access denied /
;   query error / stopped differ); a service that cannot be checked or stopped stops the setup, and a service that cannot be
;   started again afterwards is reported to the user and to the app (never a silent success).
; - The engines: bin\x86_64 + bin\x86 (GoodbyeDPI), bin\zapret (winws, Cygwin, WinDivert 2.2.2, payloads), bin\byedpi
;   (ciadpi). The user's domain lists live in data\lists with the other settings; data\ is never part of the package.
; - On uninstall "NSFShield.exe --uninstall --quiet" runs first – only when it is exactly the program this setup installed
;   (SHA-256 recorded at the installation, locked while it is checked and run, its own folder check): the service, the
;   startup task, the WinDivert registration, Windows proxy and DNS changes are undone. An unverified program is removed
;   instead of being run with administrator rights.
; - The app's automatic update runs this package with /VERYSILENT /NSFUPDATED=<old version> /NSFRESUME=0|1.

#ifndef AppVersion
  #error AppVersion is not defined; build the setup package with build.ps1.
#endif
#ifndef SourceDir
  #error SourceDir is not defined; build the setup package with build.ps1.
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif
#ifndef TouchDate
  #define TouchDate "current"
#endif
#ifndef TouchTime
  #define TouchTime "current"
#endif

#define AppName "NSF Shield"
#define AppExe "NSFShield.exe"
#define AppPublisher "Nightshift (Osman Barış MEDİNE)"
#define AppUrl "https://github.com/Mr-Leywin/nsf-shield"
#define AppCopyright "Copyright (c) 2026 Nightshift (Osman Barış MEDİNE)"

[Setup]
; AppId must equal Updater.InnoAppId in the app (the install folder is read from the uninstall entry)
AppId={{1B0AAA19-BCF0-40C5-9E22-77192CC33415}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
AppCopyright={#AppCopyright}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoCopyright={#AppCopyright}
DefaultDirName={autopf}\{#AppName}
DisableDirPage=yes
UsePreviousAppDir=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutDir}
OutputBaseFilename=NSF-Shield-{#AppVersion}-Setup
#ifdef IconFile
SetupIconFile={#IconFile}
#endif
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; the app is closed by our own --prepare-upgrade command instead of the Restart Manager
CloseApplications=no
RestartApplications=no
; two setups of this app never run at the same time
SetupMutex=NSFShieldSetup
SetupLogging=yes
; the setup language follows the Windows display language (Turkish or English)
ShowLanguageDialog=no
LanguageDetectionMethod=uilanguage
; reproducibility: installed files get a fixed date (build.ps1 passes the source time)
TimeStampsInUTC=yes
TouchDate={#TouchDate}
TouchTime={#TouchTime}
#ifdef SIGN
; signing hook: build.ps1 passes /DSIGN and /Snsfsign=... when NSF_SIGN_ARGS is set
SignTool=nsfsign
SignedUninstaller=yes
#endif

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"

[CustomMessages]
en.DesktopIcon=Create a desktop shortcut
en.ExtraIcons=Additional shortcuts:
en.AppComment=GoodbyeDPI control panel
en.GuideName=Guide
en.LaunchNow=Start NSF Shield now
en.NeedDotNet=NSF Shield needs .NET Framework 4.8.%n%nUpdate your computer with Windows Update or install .NET Framework 4.8 from Microsoft's website, then run the setup again.
en.DeleteData=Should the settings, custom profiles and logs (data folder) be deleted too?%n%nIf you choose No, your settings come back when you install NSF Shield again.
en.UnsafeDir=The install folder %1 could not be verified as protected (a link on the way, another owner, write permissions of other accounts, or it cannot be read).%n%nSetup did not install or run anything. Fix the folder or its permissions, then run setup again.
en.ServiceNotStopped=The NSF Shield background service of this folder could not be checked or stopped.%n%nNo file was changed. Restart Windows and run setup again.
en.ProcessesNotStopped=A program of this NSF Shield folder could not be closed.%n%nNo file was changed. Close NSF Shield (or restart Windows) and run setup again.
en.ServiceNotRestored=NSF Shield was installed, but its background service (protection) could not be started again. Open NSF Shield and start protection.
tr.DesktopIcon=Masaüstüne kısayol oluştur
tr.ExtraIcons=Ek kısayollar:
tr.AppComment=GoodbyeDPI kontrol paneli
tr.GuideName=Kullanım Rehberi
tr.LaunchNow=NSF Shield'i şimdi başlat
tr.NeedDotNet=NSF Shield için .NET Framework 4.8 gerekir.%n%nWindows Update ile bilgisayarınızı güncelleyin ya da .NET Framework 4.8'i Microsoft'un sitesinden kurun, sonra kurulumu yeniden çalıştırın.
tr.DeleteData=Ayarlar, özel profiller ve günlükler (data klasörü) de silinsin mi?%n%nHayır derseniz NSF Shield'i yeniden kurduğunuzda ayarlarınız geri gelir.
tr.UnsafeDir=Kurulum klasörü %1 korumalı olarak doğrulanamadı (yolda bir bağlantı, başka bir sahip, diğer hesapların yazma izni ya da okunamıyor).%n%nKurulum hiçbir şeyi kurmadı ve çalıştırmadı. Klasörü ya da izinlerini düzeltip kurulumu yeniden çalıştırın.
tr.ServiceNotStopped=Bu klasörün NSF Shield arka plan hizmeti denetlenemedi ya da durdurulamadı.%n%nHiçbir dosya değiştirilmedi. Windows'u yeniden başlatıp kurulumu yeniden çalıştırın.
tr.ProcessesNotStopped=Bu NSF Shield klasörünün bir programı kapatılamadı.%n%nHiçbir dosya değiştirilmedi. NSF Shield'i kapatın (ya da Windows'u yeniden başlatın) ve kurulumu yeniden çalıştırın.
tr.ServiceNotRestored=NSF Shield kuruldu, ancak arka plan hizmeti (koruma) yeniden başlatılamadı. NSF Shield'i açın ve korumayı başlatın.

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:ExtraIcons}"; Flags: unchecked

[Files]
; the data\ folder is not in the package; the app creates it on first start and an upgrade never touches it
Source: "{#SourceDir}\*"; Excludes: "*.sys"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs touch
; Kernel drivers (WinDivert*.sys, and the drivers of other engines later). A loaded driver keeps its file locked even
; after GoodbyeDPI and the service have stopped; PrepareToInstall unloads it first (ReleaseDrivers). As a last line of
; defence a .sys file is compared by its version (no ignoreversion): the same version is kept as it is, so an upgrade
; that ships the same driver never has to touch a locked file; a newer driver that is still locked is replaced at the
; next restart instead of stopping the setup halfway (restartreplace; the app's updates run with /NORESTART).
Source: "{#SourceDir}\*.sys"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs touch restartreplace uninsrestartdelete
; the NEW program of this package checks the target folder from the setup's temporary folder before anything is run there
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{tmp}"; DestName: "NSFShieldSetupCheck.exe"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "{cm:AppComment}"
; the guide opens through a fixed entry page of the setup language (a plain file path; Guide.html itself has both languages)
Name: "{autoprograms}\{#AppName} {cm:GuideName}"; Filename: "{app}\guide\en.html"; Languages: en
Name: "{autoprograms}\{#AppName} {cm:GuideName}"; Filename: "{app}\guide\tr.html"; Languages: tr
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

; The NSFShield.exe manifest is requireAdministrator: started without rights, CreateProcess fails with 740 ("elevation required").
; Inno Setup runs postinstall entries by default with the first user's unelevated identity (runasoriginaluser);
; setup is already elevated, so every entry is started as administrator with runascurrentuser (no second UAC prompt).
; Exec calls in [Code] also run with the setup's administrator identity (ExecAsOriginalUser is not used).
; Both entries start the program only from a folder verified as protected again after the files were copied (AppDirOk).
[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchNow}"; Flags: nowait postinstall skipifsilent runascurrentuser; Check: AppDirOk
; after an automatic update, reopen the app with the "updated" information
Filename: "{app}\{#AppExe}"; Parameters: "--tray --updated {param:NSFUPDATED|} {code:ResumeArg}"; Flags: nowait runascurrentuser; Check: IsSilentUpdate and AppDirOk

; No [UninstallRun] entry: the clean-up program is run from [Code] (CurUninstallStepChanged, usUninstall) only after it was
; verified, while it is locked against changes. An unverified program is removed there and never started.

[Code]

function IsSilentUpdate: Boolean;
begin
  Result := WizardSilent and (ExpandConstant('{param:NSFUPDATED|}') <> '');
end;

function ResumeArg(Param: String): String;
begin
  if ExpandConstant('{param:NSFRESUME|0}') = '1' then
    Result := '--resume'
  else
    Result := '';
end;

function IsDotNet48Installed: Boolean;
var
  Release: Cardinal;
begin
  Result := RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) and (Release >= 528040);
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  if not IsDotNet48Installed then
  begin
    SuppressibleMsgBox(CustomMessage('NeedDotNet'), mbCriticalError, MB_OK, IDOK);
    Result := False;
  end;
end;

{ ---------------------------------------------------------------- Win32 API (Unicode "W" entries, stdcall)
  Strings are Unicode String, handles THandle, DWORDs Cardinal; a native BOOL is a 32-bit LongBool (never a 1-byte Boolean);
  SERVICE_STATUS is seven Cardinals. Setup itself is always a 32-bit process. }
type
  TServiceStatus = record
    dwServiceType: Cardinal;
    dwCurrentState: Cardinal;
    dwControlsAccepted: Cardinal;
    dwWin32ExitCode: Cardinal;
    dwServiceSpecificExitCode: Cardinal;
    dwCheckPoint: Cardinal;
    dwWaitHint: Cardinal;
  end;

function OpenSCManager(MachineName, DatabaseName: String; Access: Cardinal): THandle;
  external 'OpenSCManagerW@advapi32.dll stdcall';
function OpenService(SCManager: THandle; ServiceName: String; Access: Cardinal): THandle;
  external 'OpenServiceW@advapi32.dll stdcall';
function QueryServiceStatus(Service: THandle; var Status: TServiceStatus): LongBool;
  external 'QueryServiceStatus@advapi32.dll stdcall';
function CloseServiceHandle(Handle: THandle): LongBool;
  external 'CloseServiceHandle@advapi32.dll stdcall';
function GetLongPathName(ShortPath: String; LongPath: String; Size: Cardinal): Cardinal;
  external 'GetLongPathNameW@kernel32.dll stdcall';
function CreateFileW(Name: String; Access, Share, Security, Disposition, Flags: Cardinal; Template: THandle): THandle;
  external 'CreateFileW@kernel32.dll stdcall';
function GetFinalPathNameByHandleW(Handle: THandle; Buf: String; Len, Flags: Cardinal): Cardinal;
  external 'GetFinalPathNameByHandleW@kernel32.dll stdcall';
function CloseKernelHandle(Handle: THandle): LongBool;
  external 'CloseHandle@kernel32.dll stdcall';
function OpenProcess(Access: Cardinal; Inherit: LongBool; Pid: Cardinal): THandle;
  external 'OpenProcess@kernel32.dll stdcall';
function QueryFullProcessImageNameW(Process: THandle; Flags: Cardinal; Buf: String; var Size: Cardinal): LongBool;
  external 'QueryFullProcessImageNameW@kernel32.dll stdcall';
function TerminateProcess(Process: THandle; ExitCode: Cardinal): LongBool;
  external 'TerminateProcess@kernel32.dll stdcall';
function WaitForSingleObject(Handle: THandle; Milliseconds: Cardinal): Cardinal;
  external 'WaitForSingleObject@kernel32.dll stdcall';

const
  SC_MANAGER_CONNECT = $0001;
  SERVICE_QUERY_STATUS = $0004;
  ERROR_ACCESS_DENIED = 5;
  ERROR_SERVICE_DOES_NOT_EXIST = 1060;
  INVALID_HANDLE = $FFFFFFFF;
  GENERIC_READ = $80000000;
  FILE_READ_ATTRIBUTES = $80;
  FILE_SHARE_READ = 1;
  FILE_SHARE_ALL = 7;
  OPEN_EXISTING = 3;
  FILE_FLAG_BACKUP_SEMANTICS = $02000000;
  PROCESS_TERMINATE = $0001;
  PROCESS_QUERY_LIMITED_INFORMATION = $1000;
  SYNCHRONIZE = $00100000;
  WAIT_OBJECT_0 = 0;
  { results of ServiceState besides the SERVICE_* states (1 stopped, 2 start pending, 3 stop pending, 4 running, ...) }
  SVC_NOT_FOUND = -1;
  SVC_ACCESS_DENIED = -2;
  SVC_QUERY_ERROR = -3;
  { results of the folder check (NSFShield.exe --check-install-dir, run from the setup's own temporary folder) }
  DIR_PROTECTED = 0;
  DIR_ABSENT = 1;

var
  ServiceWasRunning: Boolean;
  InstallDone: Boolean;
  UninstallLock: THandle;

function ValidHandle(H: THandle): Boolean;
begin
  Result := (H <> 0) and (H <> INVALID_HANDLE);
end;

{ ---------------------------------------------------------------- service state through the Win32 SCM API (no text parsing) }

{ State of a service read numerically from the SCM with the least rights (connect + query status): SERVICE_* (1 = stopped,
  3 = stop pending, 4 = running), or SVC_NOT_FOUND, SVC_ACCESS_DENIED, SVC_QUERY_ERROR – told apart, never guessed from
  localized "sc query" text. }
function ServiceState(Name: String): Integer;
var
  Manager, Service: THandle;
  Status: TServiceStatus;
  Err: Cardinal;
begin
  Result := SVC_QUERY_ERROR;
  Manager := OpenSCManager('', 'ServicesActive', SC_MANAGER_CONNECT);
  if Manager = 0 then
  begin
    if DLLGetLastError = ERROR_ACCESS_DENIED then
      Result := SVC_ACCESS_DENIED;
    Exit;
  end;
  try
    Service := OpenService(Manager, Name, SERVICE_QUERY_STATUS);
    if Service = 0 then
    begin
      Err := DLLGetLastError;
      if Err = ERROR_SERVICE_DOES_NOT_EXIST then
        Result := SVC_NOT_FOUND
      else if Err = ERROR_ACCESS_DENIED then
        Result := SVC_ACCESS_DENIED;
      Exit;
    end;
    try
      if QueryServiceStatus(Service, Status) then
        Result := Status.dwCurrentState
      else if DLLGetLastError = ERROR_ACCESS_DENIED then
        Result := SVC_ACCESS_DENIED;
    finally
      CloseServiceHandle(Service);
    end;
  finally
    CloseServiceHandle(Manager);
  end;
end;

function StateText(State: Integer): String;
begin
  case State of
    SVC_NOT_FOUND: Result := 'not found';
    SVC_ACCESS_DENIED: Result := 'access denied';
    SVC_QUERY_ERROR: Result := 'query error';
    1: Result := 'stopped';
    2: Result := 'start pending';
    3: Result := 'stop pending';
    4: Result := 'running';
  else
    Result := 'state ' + IntToStr(State);
  end;
end;

{ ---------------------------------------------------------------- physical paths }

{ The physical path Windows resolves an existing file or folder to (GetFinalPathNameByHandleW); '' if it cannot be opened. }
function PhysicalPath(P: String): String;
var
  H: THandle;
  Buf: String;
  N: Cardinal;
begin
  Result := '';
  H := CreateFileW(P, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
  if not ValidHandle(H) then
    Exit;
  try
    SetLength(Buf, 1024);
    N := GetFinalPathNameByHandleW(H, Buf, 1024, 0);
    if (N > 0) and (N < 1024) then
      Result := Copy(Buf, 1, N);
  finally
    CloseKernelHandle(H);
  end;
end;

{ Do two existing paths resolve to the same physical file? (Both must be readable.) }
function SamePhysical(A, B: String): Boolean;
var
  PA, PB: String;
begin
  PA := PhysicalPath(A);
  PB := PhysicalPath(B);
  Result := (PA <> '') and (PB <> '') and (CompareText(PA, PB) = 0);
end;

{ Is an existing file physically inside the folder? }
function PhysicalInFolder(P, Dir: String): Boolean;
var
  PF, PD: String;
begin
  PF := PhysicalPath(P);
  PD := PhysicalPath(Dir);
  Result := (PF <> '') and (PD <> '') and (CompareText(Copy(PF, 1, Length(PD) + 1), AddBackslash(PD)) = 0);
end;

{ The long form of an existing path (8.3 short names expanded); the path itself if it cannot be expanded. }
function LongPathOf(P: String): String;
var
  Buf: String;
  N: Cardinal;
begin
  Result := P;
  SetLength(Buf, 1024);
  N := GetLongPathName(P, Buf, 1024);
  if (N > 0) and (N < 1024) then
    Result := Copy(Buf, 1, N);
end;

{ The file of a service or driver image path (\??\C:\..., "C:\...\x.exe" args, C:\...\x.sys). }
function ImageFile(Image: String): String;
var
  P: Integer;
begin
  Result := Trim(Image);
  if Pos('\??\', Result) = 1 then
    Delete(Result, 1, 4);
  if Copy(Result, 1, 1) = '"' then
  begin
    Delete(Result, 1, 1);
    P := Pos('"', Result);
    if P > 0 then
      Result := Copy(Result, 1, P - 1);
  end
  else
  begin
    P := Pos('.exe', Lowercase(Result));
    if P > 0 then
      Result := Copy(Result, 1, P + 3);
  end;
end;

{ The executables this installation may stop: the engines, the proxy recovery helper and (IncludeApp) the app itself. }
function AllowedExes(IncludeApp: Boolean): TArrayOfString;
begin
  SetArrayLength(Result, 5 + Ord(IncludeApp));
  Result[0] := ExpandConstant('{app}\bin\x86_64\goodbyedpi.exe');
  Result[1] := ExpandConstant('{app}\bin\x86\goodbyedpi.exe');
  Result[2] := ExpandConstant('{app}\bin\zapret\winws.exe');
  Result[3] := ExpandConstant('{app}\bin\byedpi\ciadpi.exe');
  Result[4] := ExpandConstant('{app}\bin\NSFShieldProxyRecovery.exe');
  if IncludeApp then
    Result[5] := ExpandConstant('{app}\{#AppExe}');
end;

{ Does a file resolve physically to one of the allowed executables of this folder? }
function IsAllowedExe(P: String; IncludeApp: Boolean): Boolean;
var
  Allowed: TArrayOfString;
  I: Integer;
  PP, PA: String;
begin
  Result := False;
  PP := PhysicalPath(P);
  if PP = '' then
    Exit;
  Allowed := AllowedExes(IncludeApp);
  for I := 0 to GetArrayLength(Allowed) - 1 do
  begin
    PA := PhysicalPath(Allowed[I]);
    if (PA <> '') and (CompareText(PP, PA) = 0) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

{ ---------------------------------------------------------------- the install folder is checked before anything in it runs }

{ FILE_ATTRIBUTE_REPARSE_POINT ($400) is predefined by Inno Setup.
  Is this existing file or folder a reparse point (junction, symbolic link, mount point)? An entry that cannot be read counts as one. }
function IsReparse(Path: String): Boolean;
var
  Rec: TFindRec;
begin
  Result := False;
  if FindFirst(RemoveBackslashUnlessRoot(Path), Rec) then
  begin
    try
      Result := (Rec.Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0;
    finally
      FindClose(Rec);
    end;
  end
  else
    Result := DirExists(Path) or FileExists(Path);
end;

{ No junction or symbolic link in the folder, any of its parents, or the program file in it. }
function NoLinksOnTheWay(Dir, Exe: String): Boolean;
var
  P, Parent: String;
begin
  Result := False;
  P := RemoveBackslashUnlessRoot(Dir);
  while Length(P) > 3 do
  begin
    if IsReparse(P) then
    begin
      Log('Reparse point on the way: ' + P);
      Exit;
    end;
    Parent := ExtractFileDir(P);
    if Parent = P then
      Break;
    P := Parent;
  end;
  if FileExists(Exe) and IsReparse(Exe) then
  begin
    Log('The program file is a link: ' + Exe);
    Exit;
  end;
  Result := True;
end;

{ Runs the folder check of a NSFShield.exe: its exit code (0 protected, 1 not there yet, 2 unsafe, 3 not readable), or -1
  when it could not run. The reason it gives is written to the setup log. }
function RunDirCheck(Checker, Dir, Report: String): Integer;
var
  RC: Integer;
  Text: AnsiString;
begin
  Result := -1;
  DeleteFile(Report);
  if not Exec(Checker, '--check-install-dir "' + Dir + '" "' + Report + '"', '', SW_HIDE, ewWaitUntilTerminated, RC) then
  begin
    Log('The folder check could not be run: ' + SysErrorMessage(RC));
    Exit;
  end;
  Result := RC;
  if LoadStringFromFile(Report, Text) then
    Log('Folder check of ' + Dir + ': ' + String(Text))
  else
    Log('Folder check of ' + Dir + ': exit code ' + IntToStr(RC));
  DeleteFile(Report);
end;

{ The install folder checked by the NEW program of this package, run from the setup's own temporary folder (never a
  program in the target): the physical path, no link on the way, the owner and the write permissions of the folder, its
  program, the used subfolders and every parent. Fresh on every call (the Program Files prefix alone proves nothing). }
function CheckAppDir: Integer;
begin
  Result := -1;
  try
    ExtractTemporaryFile('NSFShieldSetupCheck.exe');
  except
    Log('The folder check program could not be extracted: ' + GetExceptionMessage);
    Exit;
  end;
  Result := RunDirCheck(ExpandConstant('{tmp}\NSFShieldSetupCheck.exe'), ExpandConstant('{app}'), ExpandConstant('{tmp}\dircheck.txt'));
end;

{ The folder exists and is verified as protected: only then a program in it may run with the setup's administrator rights. }
function AppDirTrusted: Boolean;
begin
  Result := CheckAppDir = DIR_PROTECTED;
  if not Result then
    Log('The install folder is not verified as protected: ' + ExpandConstant('{app}'));
end;

{ [Run]: the program is started only from the verified folder. }
function AppDirOk: Boolean;
begin
  Result := AppDirTrusted;
end;

{ ---------------------------------------------------------------- drivers, processes and the service of this folder }

{ The WinDivert driver stays loaded after GoodbyeDPI exits and keeps its .sys file in this folder locked (DeleteFile
  error 5). Unload it only if its file is physically in this folder: "sc stop" (never "sc delete") and wait at most 10 s
  until it has stopped. A driver marked for deletion disappears when it stops, which also counts as released. A state that
  cannot be read (access denied, query error) is logged and the driver is left alone. }
procedure ReleaseDriver(Name: String);
var
  RC, I, State: Integer;
  Image: String;
begin
  State := ServiceState(Name);
  if (State = SVC_NOT_FOUND) or (State = 1) then
    Exit;
  if (State = SVC_ACCESS_DENIED) or (State = SVC_QUERY_ERROR) then
  begin
    Log('Driver ' + Name + ': ' + StateText(State) + '; left alone.');
    Exit;
  end;
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\' + Name, 'ImagePath', Image) then
    Exit;
  if not PhysicalInFolder(ImageFile(Image), ExpandConstant('{app}')) then
  begin
    Log('Driver ' + Name + ' was not loaded from this folder; left alone.');
    Exit;
  end;
  if State <> 3 then
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop "' + Name + '"', '', SW_HIDE, ewWaitUntilTerminated, RC);
  for I := 1 to 20 do
  begin
    State := ServiceState(Name);
    if (State = SVC_NOT_FOUND) or (State = 1) then
    begin
      Log('Driver ' + Name + ' unloaded.');
      Exit;
    end;
    Sleep(500);
  end;
  Log('Driver ' + Name + ' is still loaded (' + StateText(State) + '); a locked .sys file is replaced at the next restart.');
end;

{ The process ids of an image name (tasklist CSV: "name","pid",...; any other line is skipped). }
function PidsOf(Image: String): TArrayOfString;
var
  RC, I, P, N: Integer;
  Output: TExecOutput;
  Line, Rest: String;
begin
  SetArrayLength(Result, 0);
  if not ExecAndCaptureOutput(ExpandConstant('{sys}\tasklist.exe'), '/FI "IMAGENAME eq ' + Image + '" /FO CSV /NH', '', SW_HIDE, ewWaitUntilTerminated, RC, Output) then
    Exit;
  N := 0;
  for I := 0 to GetArrayLength(Output.StdOut) - 1 do
  begin
    Line := Trim(Output.StdOut[I]);
    if Pos('"' + Lowercase(Image) + '","', Lowercase(Line)) <> 1 then
      Continue;
    Rest := Copy(Line, Length(Image) + 5, Length(Line));
    P := Pos('"', Rest);
    if (P > 1) and (StrToIntDef(Copy(Rest, 1, P - 1), 0) > 0) then
    begin
      SetArrayLength(Result, N + 1);
      Result[N] := Copy(Rest, 1, P - 1);
      N := N + 1;
    end;
  end;
end;

{ Is a WinDivert program (GoodbyeDPI or zapret's winws) still running – one of another program, ours were closed before?
  Then the driver it uses is left alone. }
function OtherDriverUserRunning: Boolean;
begin
  Result := (GetArrayLength(PidsOf('goodbyedpi.exe')) > 0) or (GetArrayLength(PidsOf('winws.exe')) > 0);
end;

{ Closes one process only when its executable – read through the same handle that closes it, so a reused process id is
  never hit – resolves physically to an allowed executable of this folder. 1 closed, 0 not ours (or its path cannot be
  read: left running), -1 ours but it did not end. }
function CloseIfOurs(Pid: Cardinal; IncludeApp: Boolean): Integer;
var
  H: THandle;
  Buf, Path: String;
  Size: Cardinal;
  Ended: Boolean;
begin
  Result := 0;
  H := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_TERMINATE or SYNCHRONIZE, False, Pid);
  if not ValidHandle(H) then
  begin
    Log('Process ' + IntToStr(Pid) + ' could not be opened; left alone.');
    Exit;
  end;
  try
    SetLength(Buf, 1024);
    Size := 1024;
    if not QueryFullProcessImageNameW(H, 0, Buf, Size) then
    begin
      Log('The path of process ' + IntToStr(Pid) + ' could not be read; left alone.');
      Exit;
    end;
    Path := Copy(Buf, 1, Size);
    if not IsAllowedExe(Path, IncludeApp) then
      Exit;
    Ended := False;
    if TerminateProcess(H, 1) then
      Ended := WaitForSingleObject(H, 5000) = WAIT_OBJECT_0;
    if Ended then
    begin
      Log('Closed: ' + Path + ' (PID ' + IntToStr(Pid) + ')');
      Result := 1;
    end
    else
    begin
      Log('Did not end: ' + Path + ' (PID ' + IntToStr(Pid) + ')');
      Result := -1;
    end;
  finally
    CloseKernelHandle(H);
  end;
end;

{ The engines of THIS folder (goodbyedpi, winws, ciadpi), the proxy recovery helper and, with IncludeApp, NSFShield.exe of
  this folder: matched by the physical full path of the allowed executables (never by name alone); other programs' copies
  and other installations keep running. False when a process of this folder did not end. }
function StopFolderProcesses(IncludeApp: Boolean): Boolean;
var
  Names, Pids: TArrayOfString;
  I, J: Integer;
begin
  Result := True;
  SetArrayLength(Names, 4 + Ord(IncludeApp));
  Names[0] := 'goodbyedpi.exe';
  Names[1] := 'winws.exe';
  Names[2] := 'ciadpi.exe';
  Names[3] := 'NSFShieldProxyRecovery.exe';
  if IncludeApp then
    Names[4] := '{#AppExe}';
  for I := 0 to GetArrayLength(Names) - 1 do
  begin
    Pids := PidsOf(Names[I]);
    for J := 0 to GetArrayLength(Pids) - 1 do
      if CloseIfOurs(StrToIntDef(Pids[J], 0), IncludeApp) < 0 then
        Result := False;
  end;
end;

{ Does a service image run an allowed engine of this folder (physical path)? }
function ServiceImageOurs(Image: String): Boolean;
begin
  Result := IsAllowedExe(ImageFile(Image), False);
end;

{ The NSFShield service is stopped by setup itself only when it runs an engine of this folder (physical path); the service of
  another installation is left alone. 1: it was running and is stopped now; 0: nothing to do (not there, stopped, or another
  installation's); -1: its state or owner cannot be read, or it did not stop – setup must not go on. }
function StopOwnService: Integer;
var
  RC, I, State: Integer;
  Image: String;
begin
  Result := 0;
  State := ServiceState('NSFShield');
  if State = SVC_NOT_FOUND then
    Exit;
  if (State = SVC_ACCESS_DENIED) or (State = SVC_QUERY_ERROR) then
  begin
    Log('NSFShield service: ' + StateText(State) + '; it cannot be checked.');
    Result := -1;
    Exit;
  end;
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\NSFShield', 'ImagePath', Image) then
  begin
    Log('NSFShield service: its program cannot be read.');
    Result := -1;
    Exit;
  end;
  if not ServiceImageOurs(Image) then
  begin
    Log('The NSFShield service runs a program of another folder; left alone.');
    Exit;
  end;
  if State = 1 then
    Exit;
  if State <> 3 then
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop NSFShield', '', SW_HIDE, ewWaitUntilTerminated, RC);
  for I := 1 to 60 do
  begin
    State := ServiceState('NSFShield');
    if (State = SVC_NOT_FOUND) or (State = 1) then
      Break;
    Sleep(500);
  end;
  if (State = SVC_NOT_FOUND) or (State = 1) then
  begin
    Log('NSFShield service of this folder stopped.');
    Result := 1;
  end
  else
  begin
    Log('NSFShield service of this folder did not stop: ' + StateText(State) + '.');
    Result := -1;
  end;
end;

procedure ReleaseDrivers;
begin
  if OtherDriverUserRunning then
  begin
    Log('Another WinDivert program (GoodbyeDPI/winws) is running; the WinDivert driver is left loaded.');
    Exit;
  end;
  ReleaseDriver('WinDivert');
  ReleaseDriver('WinDivert1.4');
  ReleaseDriver('WinDivert14');
end;

{ Starts the service of this folder again and checks that it runs; True only when the SCM reports it running. }
function StartServiceLogged: Boolean;
var
  RC, I, State: Integer;
  Image: String;
begin
  Result := False;
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\NSFShield', 'ImagePath', Image) or not ServiceImageOurs(Image) then
  begin
    Log('The NSFShield service is not this folder''s (or cannot be read); it is not started.');
    Exit;
  end;
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'start NSFShield', '', SW_HIDE, ewWaitUntilTerminated, RC) then
    Log('sc start NSFShield could not be run: ' + SysErrorMessage(RC))
  else
    Log('sc start NSFShield exit code: ' + IntToStr(RC));
  State := ServiceState('NSFShield');
  for I := 1 to 30 do
  begin
    if State <> 2 then
      Break;
    Sleep(500);
    State := ServiceState('NSFShield');
  end;
  Result := State = 4;
  Log('NSFShield service: ' + StateText(State) + '.');
end;

{ The files are installed but protection did not come back: told to the user (unless silent) and to the app, which shows it
  at its next start (data\setup-result.txt). Never a silent success. }
procedure ReportServiceNotRestored;
var
  Data: String;
begin
  Log('Protection (the background service) could not be started again after the setup.');
  Data := ExpandConstant('{app}\data');
  if DirExists(Data) and not IsReparse(Data) then
    SaveStringToFile(Data + '\setup-result.txt', 'service-not-restored' + #13#10, False);
  if not WizardSilent then
    MsgBox(CustomMessage('ServiceNotRestored'), mbError, MB_OK);
end;

{ ---------------------------------------------------------------- setup steps }

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC, State, DirState: Integer;
  Exe: String;
  Prepared: Boolean;
begin
  Result := '';
  ServiceWasRunning := False;
  DirState := CheckAppDir;
  if (DirState <> DIR_PROTECTED) and (DirState <> DIR_ABSENT) then
  begin
    { an unsafe or unreadable target (or a check that could not run): nothing is installed and nothing in it runs }
    Result := FmtMessage(CustomMessage('UnsafeDir'), [ExpandConstant('{app}')]);
    Exit;
  end;
  Exe := ExpandConstant('{app}\{#AppExe}');
  if (DirState = DIR_ABSENT) or not FileExists(Exe) then
    Exit;
  Prepared := False;
  { the folder is verified as protected: the installed version stops the app, its engines and the service of this folder;
    settings and system changes are not touched }
  if Exec(Exe, '--prepare-upgrade', '', SW_HIDE, ewWaitUntilTerminated, RC) then
  begin
    Log('--prepare-upgrade exit code: ' + IntToStr(RC));
    Prepared := (RC = 0) or (RC = 10);
    ServiceWasRunning := RC = 10;
  end
  else
    Log('--prepare-upgrade could not be run: ' + SysErrorMessage(RC));
  { setup makes sure itself (a failed preparation or the leftovers): the service
    of this folder and the processes of this folder, matched by their physical paths }
  State := StopOwnService;
  if State < 0 then
  begin
    if ServiceWasRunning then
      StartServiceLogged;
    Result := CustomMessage('ServiceNotStopped');
    Exit;
  end;
  if State = 1 then
    ServiceWasRunning := True;
  if not StopFolderProcesses(True) then
  begin
    if ServiceWasRunning and not StartServiceLogged then
      Log('The service could not be started again after the stopped setup.');
    Result := CustomMessage('ProcessesNotStopped');
    Exit;
  end;
  if not Prepared then
    Log('Setup stopped the service and the processes of this folder itself.');
  ReleaseDrivers;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallDone := True;
    { the uninstaller runs the clean-up program only when it is still exactly this one }
    RegWriteStringValue(HKLM64, 'Software\NSFShield\Setup', 'AppExeSha256', GetSHA256OfFile(ExpandConstant('{app}\{#AppExe}')));
    { if the service was running before the upgrade, protection comes back at once (even if the app is not opened); a
      failure is reported, never only logged }
    if ServiceWasRunning and not StartServiceLogged then
      ReportServiceNotRestored;
  end;
end;

procedure DeinitializeSetup;
var
  RC: Integer;
  Exe: String;
begin
  { if a silent update failed, Inno Setup has rolled the files back: protection and the old version come back }
  if IsSilentUpdate and (not InstallDone) then
  begin
    try
      if ServiceWasRunning and not StartServiceLogged then
        ReportServiceNotRestored;
      { the old program is reopened only from a folder verified as protected right now }
      Exe := ExpandConstant('{app}\{#AppExe}');
      if FileExists(Exe) and AppDirTrusted then
        Exec(Exe, '--tray --update-failed ' + ResumeArg(''), '', SW_SHOWNORMAL, ewNoWait, RC);
    except
      Log('The old version could not be reopened after the failed update.');
    end;
  end;
end;

{ ---------------------------------------------------------------- uninstall }

{ The clean-up program (NSFShield.exe --uninstall) runs with administrator rights only when it is exactly the program this
  setup installed: no link on the way, locked against changes (write and delete denied) while it is checked and run, the
  SHA-256 recorded at the installation, and its own check of the folder (owner, write permissions, physical path). }
function UninstallExeVerified(Exe: String): Boolean;
var
  Recorded, Report: String;
begin
  Result := False;
  if not FileExists(Exe) then
    Exit;
  if not NoLinksOnTheWay(ExpandConstant('{app}'), Exe) then
    Exit;
  UninstallLock := CreateFileW(Exe, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
  if not ValidHandle(UninstallLock) then
  begin
    Log('The clean-up program could not be locked.');
    Exit;
  end;
  if not RegQueryStringValue(HKLM64, 'Software\NSFShield\Setup', 'AppExeSha256', Recorded) then
  begin
    Log('No recorded program hash.');
    Exit;
  end;
  if CompareText(GetSHA256OfFile(Exe), Recorded) <> 0 then
  begin
    Log('The program changed since it was installed.');
    Exit;
  end;
  Report := AddBackslash(GetTempDir) + 'nsfshield-uninstall-check.txt';
  Result := RunDirCheck(Exe, ExpandConstant('{app}'), Report) = DIR_PROTECTED;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  RC: Integer;
  Exe, Data: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    { the service, the startup task, the WinDivert registration, Windows proxy and DNS changes are undone by the app }
    Exe := ExpandConstant('{app}\{#AppExe}');
    if UninstallExeVerified(Exe) then
    begin
      if Exec(Exe, '--uninstall --quiet', '', SW_HIDE, ewWaitUntilTerminated, RC) then
        Log('--uninstall exit code: ' + IntToStr(RC))
      else
        Log('--uninstall could not be run: ' + SysErrorMessage(RC));
      CloseKernelHandle(UninstallLock);
      UninstallLock := 0;
    end
    else
    begin
      if ValidHandle(UninstallLock) then
        CloseKernelHandle(UninstallLock);
      UninstallLock := 0;
      { an unverified program never runs with administrator rights }
      Log('The program in the install folder could not be verified; its clean-up is not run and the file is removed.');
      if FileExists(Exe) then
        DeleteFile(Exe);
    end;
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteKeyIncludingSubkeys(HKLM64, 'Software\NSFShield\Setup');
    RegDeleteKeyIfEmpty(HKLM64, 'Software\NSFShield');
    Data := ExpandConstant('{app}\data');
    if DirExists(Data) and (not UninstallSilent) then
      if MsgBox(CustomMessage('DeleteData'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        { a link is never followed (only the physical folder of this installation is deleted) }
        if IsReparse(Data) then
          Log('The data folder is a link; nothing was deleted.')
        else
          DelTree(Data, True, True, True);
      end;
    RemoveDir(ExpandConstant('{app}'));
  end;
end;
