; AccountManager.nsi

; Definições
!define APPNAME "Account Manager"
!define COMPANYNAME "Thiago Lage"
!define DESCRIPTION "Um gerenciador de contas seguro"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0

; Incluir bibliotecas modernas de UI
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; Configurações gerais
Name "${APPNAME}"
OutFile "AccountManagerSetup.exe"
InstallDir "$PROGRAMFILES\${COMPANYNAME}\${APPNAME}"
InstallDirRegKey HKCU "Software\${COMPANYNAME}\${APPNAME}" ""

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

; Instalador
Section "Instalar" SecInstall
  SetOutPath "$INSTDIR"
  
  ; Verificar se os arquivos existem antes de copiar
  !define DIST_DIR "dist"
  !ifdef DIST_DIR
    File /r "${DIST_DIR}\*.*"
  !else
    MessageBox MB_OK|MB_ICONSTOP "Diretório 'dist' não encontrado. Certifique-se de que o diretório existe e contém os arquivos necessários."
    Abort "Instalação cancelada devido à falta de arquivos."
  !endif
  
  ; Copiar o ícone se existir
  !ifdef MUI_ICON
    File "${MUI_ICON}"
  !endif
  
  ; Criar atalho no menu iniciar
  CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
  CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk" "$INSTDIR\Account Manager.exe" "" "$INSTDIR\icon.ico"
  
  ; Escrever informações de desinstalação
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "NoRepair" 1
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; Desinstalador
Section "Uninstall"
  Delete "$INSTDIR\AccountManager.exe"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\*.pyd"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\uninstall.exe"
  
  RMDir /r "$INSTDIR"
  
  Delete "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk"
  RMDir "$SMPROGRAMS\${COMPANYNAME}"
  
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}"
SectionEnd