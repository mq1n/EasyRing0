#include <ntddk.h> 
#include <windef.h>

#define SUM_IO_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)  
#define DIFF_IO_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)  
#define MSG_IO_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)  

const WCHAR sc_wszDeviceNameBuffer[]	= L"\\Device\\IOCTL_Test";
const WCHAR sc_wszDeviceSymLinkBuffer[] = L"\\DosDevices\\IOCTL_Test";

typedef struct _KERNEL_IO_SUM_DATA
{
	INT iNumberFirst;
	INT iNumberSecond;
	INT iResult;
} SKernelIOSumData, *PKernelIOSumData;

typedef struct _KERNEL_IO_DIFF_DATA
{
	INT iNumberFirst;
	INT iNumberSecond;
	INT iResult;
} SKernelIODiffData, *PKernelIODiffData;

typedef struct _KERNEL_IO_MSG_DATA
{
	CHAR szMessage[255];
	BOOL bReceived;
} SKernelIOMsgData, *PKernelIOMsgData;

#define IO_INPUT(Type)  ((Type)(pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer)) 
#define IO_OUTPUT(Type) ((Type)(pIrp->UserBuffer))

NTSTATUS OnIoControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DbgPrint("IRP_MJ_DEVICE_CONTROL handled!\n");

	NTSTATUS ntStatus = STATUS_SUCCESS;
	__try
	{
		PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
		ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
		switch (uIoControlCode)
		{
			case SUM_IO_CODE:
			{
				DbgPrint("Sum packet received\n");

				IO_OUTPUT(PKernelIOSumData)->iResult = IO_INPUT(PKernelIOSumData)->iNumberFirst + IO_INPUT(PKernelIOSumData)->iNumberSecond;
				pIrp->IoStatus.Information = sizeof(SKernelIOSumData);
			} break;

			case DIFF_IO_CODE:
			{
				DbgPrint("Diff packet received\n");

				IO_OUTPUT(PKernelIODiffData)->iResult = IO_INPUT(PKernelIODiffData)->iNumberFirst - IO_INPUT(PKernelIODiffData)->iNumberSecond;
				pIrp->IoStatus.Information = sizeof(SKernelIODiffData);
			} break;

			case MSG_IO_CODE:
			{
				DbgPrint("Msg packet received. Content: %s\n", IO_INPUT(PKernelIOMsgData)->szMessage);

				IO_OUTPUT(PKernelIOMsgData)->bReceived = TRUE;
				pIrp->IoStatus.Information = sizeof(SKernelIOMsgData);
			} break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = STATUS_UNSUCCESSFUL;
		DbgPrint("OnIoControl Exception catched!\n");
	}

	pIrp->IoStatus.Status = ntStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

NTSTATUS OnMajorFunctionCall(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
		case IRP_MJ_DEVICE_CONTROL:
			OnIoControl(pDriverObject, pIrp);
			break;

		default:
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	return STATUS_SUCCESS;
}


VOID OnDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DbgPrint("Driver unload routine triggered!\n");

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, sc_wszDeviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	if (pDriverObject && pDriverObject->DeviceObject)
	{
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	// Process params
	UNREFERENCED_PARAMETER(pRegistryPath);

	if (!pDriverObject)
	{
		DbgPrint("DispatchTestSys driver entry is null!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// Hello world!
	DbgPrint("Driver loaded, system range start in %p, Our entry at: %p\n", MmSystemRangeStart, DriverEntry);

	// Register unload routine
	pDriverObject->DriverUnload = &OnDriverUnload;

	// Veriable decleration
	NTSTATUS ntStatus = 0;

	// Normalize name and symbolic link.
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, sc_wszDeviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, sc_wszDeviceSymLinkBuffer);

	// Create the device.
	PDEVICE_OBJECT pDeviceObject = NULL;
	ntStatus = IoCreateDevice(pDriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("DispatchTestSys IoCreateDevice fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("DispatchTestSys IoCreateSymbolicLink fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Register driver major callbacks
	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		pDriverObject->MajorFunction[t] = &OnMajorFunctionCall;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrint("DispatchTestSys driver entry completed!\n");

	return STATUS_SUCCESS;
}


