; fail2commit per-user installer (T-009, FR-009, SPEC-009).
; Build with packaging\windows\build.ps1, which passes:
;   /DVERSION=x.y.z  /DSTAGE=<dir with the files below>  /DOUTFILE=<setup.exe>
; STAGE contains: fail2commit.exe, fail2commit-tray.exe, LICENSE,
; docs\windows.md and optionally NOTICE / THIRD-PARTY-NOTICES.txt.
;
; Per-user only: no elevation, nothing outside %LOCALAPPDATA%\Programs\fail2commit,
; HKCU and the user's Start Menu. The uninstaller removes only what is listed here
; and asks the CLI to roll back its own recorded integrations; third-party
; hooks, PATH entries and the user's Git configuration are left alone.

Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"

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
  File /nonfatal "${STAGE}\NOTICE"
  File /nonfatal "${STAGE}\THIRD-PARTY-NOTICES.txt"
  SetOutPath "$INSTDIR\docs"
  File "${STAGE}\docs\windows.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "fail2commit"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\fail2commit"
  CreateShortCut "$SMPROGRAMS\fail2commit\fail2commit tray.lnk" "$INSTDIR\fail2commit-tray.exe"
SectionEnd

; `fail2commit setup` installs the Git/npm/pip guards and records every change
; it makes so that uninstall-integrations can undo exactly those.
Section "Set up Git, npm and pip guards now (fail2commit setup)" SecSetup
  DetailPrint "Running fail2commit setup"
  nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" setup'
  Pop $0
  ${If} $0 != 0
    DetailPrint "fail2commit setup exited with $0; run it again from a terminal."
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
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_Core)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSetup} $(DESC_Setup)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartup} $(DESC_Startup)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  !insertmacro StopTray

  ; Roll back what `fail2commit setup` recorded (hooks, shims, startup value).
  ${If} ${FileExists} "$INSTDIR\fail2commit.exe"
    DetailPrint "Running fail2commit uninstall-integrations"
    nsExec::ExecToLog '"$INSTDIR\fail2commit.exe" uninstall-integrations'
    Pop $0
  ${EndIf}

  ; The startup value is ours only if it points into this install.
  ReadRegStr $1 HKCU "${RUN_KEY}" "${RUN_VALUE}"
  ${If} $1 == '"$INSTDIR\fail2commit-tray.exe"'
    DeleteRegValue HKCU "${RUN_KEY}" "${RUN_VALUE}"
  ${EndIf}

  Delete "$INSTDIR\fail2commit.exe"
  Delete "$INSTDIR\fail2commit-tray.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\docs\windows.md"
  RMDir "$INSTDIR\docs"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\fail2commit\fail2commit tray.lnk"
  RMDir "$SMPROGRAMS\fail2commit"
  DeleteRegKey HKCU "${UNINST_KEY}"
  ; %LOCALAPPDATA%\fail2commit (password verifiers, settings, caches) is user
  ; data and is kept; docs\windows.md says how to remove it.
SectionEnd
