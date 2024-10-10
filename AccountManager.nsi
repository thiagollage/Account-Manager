; AccountManager.nsi

; Definições
!define APPNAME "Account Manager"
!define COMPANYNAME "Thiago Lage"
!define DESCRIPTION "Um gerenciador de contas seguro"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0
!define VERSIONFULL "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"

; Incluir bibliotecas modernas de UI
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "WinVer.nsh"
!include "x64.nsh"

; Configurações gerais
Name "${APPNAME}"
OutFile "AccountManagerSetup.exe"
InstallDir "$PROGRAMFILES\${COMPANYNAME}\${APPNAME}"
InstallDirRegKey HKLM "Software\${COMPANYNAME}\${APPNAME}" ""

; Solicitar privilégios de administrador
RequestExecutionLevel admin

; Interface
!define MUI_ABORTWARNING
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"

; Páginas
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Idiomas
!insertmacro MUI_LANGUAGE "Portuguese"

; Informações de versão
VIProductVersion "${VERSIONFULL}.0"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "CompanyName" "${COMPANYNAME}"
VIAddVersionKey "LegalCopyright" "© ${COMPANYNAME}"
VIAddVersionKey "FileDescription" "${DESCRIPTION}"
VIAddVersionKey "FileVersion" "${VERSIONFULL}"
VIAddVersionKey "ProductVersion" "${VERSIONFULL}"

; Verificação de instalação prévia
Function .onInit
  ${If} ${RunningX64}
    SetRegView 64
    StrCpy $INSTDIR "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"
  ${EndIf}

  ReadRegStr $R0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString"
  StrCmp $R0 "" done
 
  MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
  "${APPNAME} já está instalado. $\n$\nClique em 'OK' para remover a versão anterior ou 'Cancelar' para cancelar esta instalação." \
  IDOK uninst
  Abort
 
uninst:
  ClearErrors
  ExecWait '$R0 _?=$INSTDIR'
 
  IfErrors no_remove_uninstaller done
    ; Você pode adicionar código aqui para remover o desinstalador, se necessário
  no_remove_uninstaller:
 
done:
FunctionEnd

; Instalador
Section "Instalar" SecInstall
  SetOutPath "$INSTDIR"
  
  ; Copiar todos os arquivos da pasta dist
  File /r "dist\AccountManager\*.*"
  
  ; Copiar arquivos visíveis
  File "icon.ico"
  File "LICENSE.txt"
  File "config.ini"
  
  ; Copiar arquivos ocultos
  SetFileAttributes "$INSTDIR\.env" FILE_ATTRIBUTE_HIDDEN
  File /oname=.env ".env"
  SetFileAttributes "$INSTDIR\CHANGELOG.md" FILE_ATTRIBUTE_HIDDEN
  File "CHANGELOG.md"
  
  ; Criar pasta docs oculta e copiar README.md
  CreateDirectory "$INSTDIR\docs"
  SetFileAttributes "$INSTDIR\docs" FILE_ATTRIBUTE_HIDDEN
  File /oname=docs\README.md "docs\README.md"
  
  ; Criar pasta para logs
  CreateDirectory "$LOCALAPPDATA\${COMPANYNAME}\${APPNAME}\Logs"
  
  ; Criar atalho no menu iniciar
  CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
  CreateShortcut "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk" "$INSTDIR\AccountManager.exe" "" "$INSTDIR\icon.ico"
  
  ; Criar atalho na área de trabalho
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\AccountManager.exe" "" "$INSTDIR\icon.ico"
  
  ; Obter a data atual
  ${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
  StrCpy $7 "$2/$1/$0"
  
  ; Calcular o tamanho da instalação
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  
  ; Escrever informações de desinstalação
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "Publisher" "${COMPANYNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayVersion" "${VERSIONFULL}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "InstallDate" "$7"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "EstimatedSize" "$0"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "NoRepair" 1
  
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; Desinstalador
Section "Uninstall"
  ; Remover arquivos e pastas
  RMDir /r "$INSTDIR\*.*"
  
  ; Remover atalhos
  Delete "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk"
  RMDir "$SMPROGRAMS\${COMPANYNAME}"
  Delete "$DESKTOP\${APPNAME}.lnk"
  
  ; Remover pasta de logs
  RMDir /r "$LOCALAPPDATA\${COMPANYNAME}\${APPNAME}"
  
  ; Remover chaves do registro
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}"
  DeleteRegKey HKLM "Software\${COMPANYNAME}\${APPNAME}"
  
  ; Remover diretório de instalação
  RMDir "$INSTDIR"
SectionEnd