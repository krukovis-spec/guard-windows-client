[Setup]
AppId={{C127A79A-6A42-45E5-8A33-855A9E2A8D4D}}
AppName=Guard
AppVersion=1.0.0
AppPublisher=AlexWeb.App
PrivilegesRequired=admin
DefaultDirName={autopf64}\Guard
DefaultGroupName=Guard
OutputBaseFilename=Guard-Setup-v1.0.0
SetupIconFile=guard\guard.ico
UninstallDisplayIcon={app}\guard.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}";

[Files]
Source: "guard\bin\Release\net48\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Guard.Core\bin\Release\net48\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Guard.Cleaner\bin\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "GuardStartHelper\bin\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "guard\guard.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Guard"; Filename: "{app}\StartHelperG.exe"; Parameters: "/startup"; WorkingDir: "{app}"; IconFilename: "{app}\guard.ico"
Name: "{autodesktop}\Guard"; Filename: "{app}\StartHelperG.exe"; Parameters: "/startup"; WorkingDir: "{app}"; IconFilename: "{app}\guard.ico"; Tasks: desktopicon


[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "GuardHelper"; ValueData: """{app}\StartHelperG.exe"" /startup"; Flags: uninsdeletevalue


[Run]
Filename: "{app}\StartHelperG.exe"; Parameters: "/startup"; Description: "Launch Guard now"; Flags: postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "{app}\Guard.Cleaner.exe"; Flags: waituntilterminated; RunOnceId: "runcleaner"

[Code]
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  // Run Guard.Cleaner.exe in checkpin mode
  if not ShellExec('', ExpandConstant('{app}\Guard.Cleaner.exe'), '/checkpin', '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
  begin
    MsgBox('Unable to run Guard uninstaller for PIN check. Uninstall cannot continue.', mbError, MB_OK);
    Result := False;
    exit;
  end;

  if ResultCode <> 0 then
  begin
    MsgBox('Guard uninstall PIN check failed or was cancelled. Uninstall aborted.', mbError, MB_OK);
    Result := False;
    exit;
  end;

  // PIN ok or not required
  Result := True;
end;