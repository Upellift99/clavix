; NSIS installer hooks, wired in through bundle.windows.nsis.installerHooks.
;
; The publisher used to be "clavixlabs", and Tauri's installer keeps the
; install directory under HKCU\Software\<publisher>\<productName>. It reads
; that key back on upgrade, both to restore the install location and to
; point the previous version's uninstaller at it (`uninstall.exe _?=<dir>`).
; Without the carry-over below, an upgrade from 0.29.0 or older finds no
; key: the old uninstaller gets an empty directory, and the installer stops
; on "unable to uninstall".
;
; This file is included before Tauri defines MANUPRODUCTKEY and PRODUCTNAME,
; hence the literal key paths.

!define CLAVIX_KEY "Software\clavix\clavix"
!define CLAVIX_LEGACY_KEY "Software\clavixlabs\clavix"

; Copies the legacy install directory to the current key when only the
; legacy one exists, and installs there. Runs before the reinstall page
; reads the key. The legacy key is removed after a successful install.
Function ClavixCarryOverInstallDir
  ReadRegStr $0 SHCTX "${CLAVIX_KEY}" ""
  ${If} $0 == ""
    ReadRegStr $0 SHCTX "${CLAVIX_LEGACY_KEY}" ""
    ${If} $0 != ""
      WriteRegStr SHCTX "${CLAVIX_KEY}" "" $0
      StrCpy $INSTDIR $0
    ${EndIf}
  ${EndIf}
FunctionEnd

; .onGUIInit runs after .onInit has set the context and the default
; directory, and before the first page. Silent installs skip it.
!define MUI_CUSTOMFUNCTION_GUIINIT ClavixCarryOverInstallDir

!macro NSIS_HOOK_PREINSTALL
  ; A silent install shows no page, so the carry-over happens here; the
  ; template has already set the output path from the old $INSTDIR.
  ${If} ${Silent}
    Call ClavixCarryOverInstallDir
    SetOutPath $INSTDIR
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DeleteRegKey SHCTX "${CLAVIX_LEGACY_KEY}"
  DeleteRegKey /ifempty SHCTX "Software\clavixlabs"
!macroend
