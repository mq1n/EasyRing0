#include <ntifs.h>
#include <windef.h>
#include "helper.h"

const WCHAR gc_wszDeviceNameBuffer[]	= L"\\Device\\ShMem_Test";
const WCHAR gc_wszDeviceSymLinkBuffer[] = L"\\DosDevices\\ShMem_Test";
const WCHAR gc_wszSharedSectionName[]	= L"\\BaseNamedObjects\\SharedMemoryTest";

PVOID	g_pSharedSection	= NULL;
PVOID	g_pSectionObj		= NULL;
HANDLE	g_hSection			= NULL;

//----------------------------------------------------------------------   

VOID ReadSharedMemory()
{
	if (!g_hSection)
		return;

	if (g_pSharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), g_pSharedSection);

	SIZE_T ulViewSize = 1024 * 10;
	NTSTATUS ntStatus = ZwMapViewOfSection(g_hSection, NtCurrentProcess(), &g_pSharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("ZwMapViewOfSection fail! Status: %p\n", ntStatus);
		ZwClose(g_hSection);
		return;
	}
	DbgPrint("ZwMapViewOfSection completed!\n");

	DbgPrint("Shared memory read data: %s\n", (PCHAR)g_pSharedSection);
}

NTSTATUS CreateSharedMemory()
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, gc_wszSharedSectionName);

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	ntStatus = ZwCreateSection(&g_hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("ZwCreateSection fail! Status: %p\n", ntStatus);
		return ntStatus;
	}
	DbgPrint("ZwCreateSection completed!\n");

	ntStatus = ObReferenceObjectByHandle(g_hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &g_pSectionObj, 0);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("ObReferenceObjectByHandle fail! Status: %p\n", ntStatus);
		return ntStatus;
	}
	DbgPrint("ObReferenceObjectByHandle completed!\n");

	// ---
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = { 0 };
	ntStatus = CreateStandardSCAndACL(&pSecurityDescriptor, &pACL);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("CreateStandardSCAndACL fail! Status: %p\n", ntStatus);
		ObDereferenceObject(g_pSectionObj);
		ZwClose(g_hSection);
		return ntStatus;
	}

	ntStatus = GrantAccess(g_hSection, pACL);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("GrantAccess fail! Status: %p\n", ntStatus);
		ExFreePool(pACL);
		ExFreePool(pSecurityDescriptor);
		ObDereferenceObject(g_pSectionObj);
		ZwClose(g_hSection);
		return ntStatus;
	}

	ExFreePool(pACL);
	ExFreePool(pSecurityDescriptor);
	
	SIZE_T ulViewSize = 0;
	ntStatus = ZwMapViewOfSection(g_hSection, NtCurrentProcess(), &g_pSharedSection, 0, lMaxSize.LowPart, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("ZwMapViewOfSection fail! Status: %p\n", ntStatus);
		ObDereferenceObject(g_pSectionObj);
		ZwClose(g_hSection);
		return ntStatus;
	}
	DbgPrint("ZwMapViewOfSection completed!\n");

	PCHAR TestString = "Message from kernel";
	memcpy(g_pSharedSection, TestString, 19);
	ReadSharedMemory();

	return ntStatus;
}

NTSTATUS OnIRPWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	char szBuffer[255] = { 0 };
	strcpy(szBuffer, pIrp->AssociatedIrp.SystemBuffer);
	DbgPrint("User message received: %s(%u)", szBuffer, strlen(szBuffer));

	if (!strcmp(szBuffer, "read_shared_memory"))
	{
		ReadSharedMemory();
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = strlen(szBuffer);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS OnMajorFunctionCall(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
		case IRP_MJ_WRITE:
			OnIRPWrite(pDriverObject, pIrp);
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

	if (g_pSharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), g_pSharedSection);

	if (g_pSectionObj)
		ObDereferenceObject(g_pSectionObj);

	if (g_hSection)
		ZwClose(g_hSection);

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, gc_wszDeviceSymLinkBuffer);

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
	RtlInitUnicodeString(&deviceNameUnicodeString, gc_wszDeviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, gc_wszDeviceSymLinkBuffer);

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

	CreateSharedMemory();

	pDeviceObject->Flags |= DO_BUFFERED_IO;

	DbgPrint("DispatchTestSys driver entry completed!\n");

	return STATUS_SUCCESS;
}


