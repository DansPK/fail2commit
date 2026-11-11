; fail2commit per-user installer (T-009, FR-009, SPEC-009).
; Build with packaging\windows\build.ps1, which passes:
;   /DVERSION=x.y.z  /DSTAGE=<dir with the files below>  /DOUTFILE=<setup.exe>
; STAGE contains: fail2commit.exe, fail2commit-tray.exe, LICENSE, logo.ico,
; docs\windows.md and optionally NOTICE / THIRD-PARTY-NOTICES.txt.
;
; Per-user install: the installer itself never elevates and writes only
; %LOCALAPPDATA%\Programs\fail2commit, HKCU and the user's Start Menu. The
; optional "machine-wide npm and pip" section starts `fail2commit machine-shims
; install` elevated (UAC prompt), which writes Program Files and the machine
; PATH (CR-013); the uninstaller removes that the same way. The uninstaller removes only what is listed here
; and asks the CLI to roll back its own recorded integrations; third-party
; hooks, PATH entries and the user's Git configuration are left alone.

Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef STAGE
  !error "pass /DSTAGE=<staging dir>"
!endif
!ifndef OUTFILE
  !define OUTFILE "fail2commit-${VERSION}-setup.exe"
!endif

!define APP "fail2commit"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\fail2commit"
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"
!define RUN_VALUE "fail2commit-tray"

Name "${APP} ${VERSION}"
OutFile "${OUTFILE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\fail2commit"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
ShowInstDetails show
SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
!define MUI_ICON "${STAGE}\logo.ico"
!define MUI_UNICON "${STAGE}\logo.ico"
; Keep the install log on screen so a failed setup step is visible.
!define MUI_FINISHPAGE_NOAUTOCLOSE
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${STAGE}\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Ask a running tray to exit (its hidden window closes on WM_CLOSE) so the
; executable can be replaced or removed. Guards stay active without it.
!macro StopTray
  FindWindow $0 "F2CTrayMain"
  ${If} $0 != 0
    SendMessage $0 0x0010 0 0
    Sleep 1000
  ${EndIf}
!macroend

Section "fail2commit (required)" SecCore
  SectionIn RO
  !insertmacro StopTray
  SetOutPath "$INSTDIR"
  File "${STAGE}\fail2commit.exe"
  File "${STAGE}\fail2commit-tray.exe"
  File "${STAGE}\LICENSE"
  File "${STAGE}\logo.ico"
  File /nonfatal "${STAGE}\NOTICE"
  File /nonfatal "${STAGE}\THIRD-PARTY-NOTICES.txt"
  SetOutPath "$INSTDIR\docs"
  File "${STAGE}\docs\windows.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\logo.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "fail2commit"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\fail2commit"
  CreateShortCut "$SMPROGRAMS\fail2commit\fail2commit tray.lnk" "$INSTDIR\fail2commit-tray.exe" "" "$INSTDIR\logo.ico"
SectionEnd

; `fail2commit setup` installs the Git/npm/pip guards and records every change
; it makes so that uninstall-integrations can undo exactly those.
Section "Set up Git, npm and pip guards now (fail2commit setup)" SecSetup
  DetailPrint "Running fail2commit setup"
  nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" setup'
  Pop $0
  ${If} $0 != 0
    DetailPrint "fail2commit setup exited with $0; run it again from a terminal."
    MessageBox MB_OK|MB_ICONEXCLAMATION "fail2commit setup did not complete (exit code $0), so the Git, npm and pip guards are NOT active.$\r$\n$\r$\nThe install log on the next page shows why. Open a new terminal and run:$\r$\n    fail2commit setup" /SD IDOK
  ${EndIf}
SectionEnd

; CR-013: Windows puts the machine PATH before the user PATH, so a Node.js or
; Python installed for all users bypasses the per-user shims. This step asks
; for administrator rights and installs shims under Program Files, first on the
; machine PATH. Skipped in silent installs (no prompt can be answered there).
Section "Guard machine-wide npm and pip (asks for administrator)" SecMachine
  ${If} ${Silent}
    DetailPrint "Silent install: machine-wide shims skipped; run 'fail2commit machine-shims install' as administrator."
  ${Else}
    DetailPrint "Asking for administrator rights: fail2commit machine-shims install"
    ExecShellWait "runas" "$INSTDIR\fail2commit.exe" "machine-shims install" SW_HIDE
    nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" machine-shims status'
    Pop $0
    ${If} $0 != 0
      DetailPrint "Machine-wide shims are not installed."
      MessageBox MB_OK|MB_ICONEXCLAMATION "Machine-wide npm and pip are NOT guarded (administrator rights were declined or the step failed).$\r$\n$\r$\nIf Node.js or Python is installed for all users, plain npm and pip bypass fail2commit. To fix it, open a terminal as administrator and run:$\r$\n    fail2commit machine-shims install" /SD IDOK
    ${EndIf}
  ${EndIf}
SectionEnd

Section /o "Start the tray at sign-in" SecStartup
  ; Written here only for installs that skipped setup; setup would also write
  ; it. Either way the uninstaller removes it.
  WriteRegStr HKCU "${RUN_KEY}" "${RUN_VALUE}" '"$INSTDIR\fail2commit-tray.exe"'
SectionEnd

; When setup ran but the user declined sign-in startup, take the value back;
; when they accepted it, start the tray now.
Function .onInstSuccess
  ${If} ${SectionIsSelected} ${SecStartup}
    Exec '"$INSTDIR\fail2commit-tray.exe"'
  ${ElseIf} ${SectionIsSelected} ${SecSetup}
    DeleteRegValue HKCU "${RUN_KEY}" "${RUN_VALUE}"
  ${EndIf}
FunctionEnd

LangString DESC_Core ${LANG_ENGLISH} "The fail2commit command line and the tray."
LangString DESC_Setup ${LANG_ENGLISH} "Runs 'fail2commit setup' for your user. Nothing outside your profile changes; every change is recorded for uninstall."
LangString DESC_Startup ${LANG_ENGLISH} "Starts the tray when you sign in so approval prompts appear as notifications. Guards stay active without it."
LangString DESC_Machine ${LANG_ENGLISH} "Needed when Node.js or Python is installed for all users: Windows searches the machine PATH first. Installs npm/pip shims under Program Files (asks for administrator)."
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_Core)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSetup} $(DESC_Setup)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMachine} $(DESC_Machine)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartup} $(DESC_Startup)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  !insertmacro StopTray

  ; Roll back what `fail2commit setup` recorded (hooks, shims, startup value).
  ${If} ${FileExists} "$INSTDIR\fail2commit.exe"
    DetailPrint "Running fail2commit uninstall-integrations"
    nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" uninstall-integrations'
    Pop $0
    ; Machine-wide shims (CR-013) need administrator rights to remove.
    nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" machine-shims status'
    Pop $0
    ${If} $0 == 0
      DetailPrint "Asking for administrator rights: fail2commit machine-shims uninstall"
      ExecShellWait "runas" "$INSTDIR\fail2commit.exe" "machine-shims uninstall" SW_HIDE
      nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" machine-shims status'
      Pop $0
      ${If} $0 == 0
        MessageBox MB_OK|MB_ICONEXCLAMATION "The machine-wide npm/pip shims are still installed (administrator rights declined).$\r$\n$\r$\nOpen a terminal as administrator and run:$\r$\n    $\"%ProgramFiles%\fail2commit\shims\fail2commit.exe$\" machine-shims uninstall" /SD IDOK
      ${EndIf}
    ${EndIf}
  ${EndIf}

  ; The startup value is ours only if it points into this install.
  ReadRegStr $1 HKCU "${RUN_KEY}" "${RUN_VALUE}"
  ${If} $1 == '"$INSTDIR\fail2commit-tray.exe"'
    DeleteRegValue HKCU "${RUN_KEY}" "${RUN_VALUE}"
  ${EndIf}

  Delete "$INSTDIR\fail2commit.exe"
  Delete "$INSTDIR\fail2commit-tray.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\logo.ico"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\docs\windows.md"
  RMDir "$INSTDIR\docs"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\fail2commit\fail2commit tray.lnk"
  RMDir "$SMPROGRAMS\fail2commit"
  DeleteRegKey HKCU "${UNINST_KEY}"

  ; User data (settings, password verifier, approvals, caches, signing-key
  ; records, the offline malware list) is kept unless the user asks: a
  ; question in the GUI (default No), or /PURGE for a silent uninstall.
  StrCpy $R2 0
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/PURGE" $R1
  ${IfNot} ${Errors}
    StrCpy $R2 1
  ${ElseIfNot} ${Silent}
    ${If} ${Cmd} `MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete your fail2commit settings and data?$\r$\n$\r$\nThis removes your approval password, settings, caches and the offline malware list from:$\r$\n    $LOCALAPPDATA\fail2commit$\r$\n    $APPDATA\fail2commit$\r$\n$\r$\nChoose No to keep them for a later reinstall." IDYES`
      StrCpy $R2 1
    ${EndIf}
  ${EndIf}
  ${If} $R2 == 1
    DetailPrint "Deleting fail2commit user data"
    RMDir /r "$LOCALAPPDATA\fail2commit"
    RMDir /r "$APPDATA\fail2commit"
  ${Else}
    ; Folders that hold nothing are removed either way (RMDir without /r
    ; deletes only empty folders).
    RMDir "$LOCALAPPDATA\fail2commit\bin"
    RMDir "$APPDATA\fail2commit"
  ${EndIf}
SectionEnd
