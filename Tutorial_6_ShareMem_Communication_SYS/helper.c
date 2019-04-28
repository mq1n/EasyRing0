#include <ntifs.h>
#include "helper.h"

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/rtl/sysvol.c

#define LongAlignPtr(Ptr) ((PVOID)(((ULONG_PTR)(Ptr) + 3) & -4))
#define LongAlignSize(Size) (((ULONG)(Size) + 3) & -4)

#define RtlpClearControlBits( SD, Bits )                                       \
            (                                                                  \
            ( SD )->Control &= ~( Bits )                                       \
            )

#define AreControlBitsSet( SD, Bits )                                          \
            (BOOLEAN)                                                          \
            (                                                                  \
            (( SD )->Control & ( Bits )) == ( Bits )  \
            )

#define OwnerAddrSecurityDescriptor( SD )                                  \
           (  ((SD)->Control & SE_SELF_RELATIVE) ?                             \
               (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Owner == 0) ? ((PSID) NULL) :               \
                       (PSID)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Owner)    \
               ) :                                                             \
               (PSID)((SD)->Owner)                                             \
           )

#define GroupAddrSecurityDescriptor( SD )                                  \
           (  ((SD)->Control & SE_SELF_RELATIVE) ?                             \
               (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Group == 0) ? ((PSID) NULL) :               \
                       (PSID)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Group)    \
               ) :                                                             \
               (PSID)((SD)->Group)                                             \
           )

#define SaclAddrSecurityDescriptor( SD )                                   \
           ( (!((SD)->Control & SE_SACL_PRESENT) ) ?                           \
             (PACL)NULL :                                                      \
               (  ((SD)->Control & SE_SELF_RELATIVE) ?                         \
                   (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Sacl == 0) ? ((PACL) NULL) :            \
                           (PACL)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Sacl) \
                   ) :                                                         \
                   (PACL)((SD)->Sacl)                                          \
               )                                                               \
           )

#define DaclAddrSecurityDescriptor( SD )                                   \
           ( (!((SD)->Control & SE_DACL_PRESENT) ) ?                           \
             (PACL)NULL :                                                      \
               (  ((SD)->Control & SE_SELF_RELATIVE) ?                         \
                   (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Dacl == 0) ? ((PACL) NULL) :            \
                           (PACL)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Dacl) \
                   ) :                                                         \
                   (PACL)((SD)->Dacl)                                          \
               )                                                               \
           )

VOID DoQuerySecurityDescriptor(__in PISECURITY_DESCRIPTOR SecurityDescriptor, __deref_out PSID *Owner, __out PULONG OwnerSize, __deref_out PSID *PrimaryGroup, __out PULONG PrimaryGroupSize, __deref_out PACL *Dacl, __out PULONG DaclSize, __deref_out PACL *Sacl, __out PULONG SaclSize)
{
	*Owner = OwnerAddrSecurityDescriptor(SecurityDescriptor);
	if (*Owner != NULL) {
		*OwnerSize = LongAlignSize(SeLengthSid(*Owner));
	}
	else {
		*OwnerSize = 0;
	}

	*Dacl = DaclAddrSecurityDescriptor(SecurityDescriptor);
	if (*Dacl != NULL) {
		*DaclSize = LongAlignSize((*Dacl)->AclSize);
	}
	else {
		*DaclSize = 0;
	}

	*PrimaryGroup = GroupAddrSecurityDescriptor(SecurityDescriptor);
	if (*PrimaryGroup != NULL) {
		*PrimaryGroupSize = LongAlignSize(SeLengthSid(*PrimaryGroup));
	}
	else {
		*PrimaryGroupSize = 0;
	}

	*Sacl = SaclAddrSecurityDescriptor(SecurityDescriptor);
	if (*Sacl != NULL) {
		*SaclSize = LongAlignSize((*Sacl)->AclSize);
	}
	else {
		*SaclSize = 0;
	}
}

NTSTATUS RtlSelfRelativeToAbsoluteSD2(PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor, PULONG pBufferSize)
{
	ULONG_PTR ptr;
	PSID owner;
	PSID group;
	PACL dacl;
	PACL sacl;
	ULONG daclSize;
	ULONG saclSize;
	ULONG ownerSize;
	ULONG groupSize;
	ULONG newBufferSize;
	LONG deltaSize;

	PISECURITY_DESCRIPTOR          psd = (PISECURITY_DESCRIPTOR)pSelfRelativeSecurityDescriptor;
	PISECURITY_DESCRIPTOR_RELATIVE psdr = (PISECURITY_DESCRIPTOR_RELATIVE)pSelfRelativeSecurityDescriptor;

	C_ASSERT(sizeof(SECURITY_DESCRIPTOR) >= sizeof(SECURITY_DESCRIPTOR_RELATIVE));
	C_ASSERT(sizeof(psd->Control) == sizeof(psdr->Control));
	C_ASSERT(FIELD_OFFSET(SECURITY_DESCRIPTOR, Control) == FIELD_OFFSET(SECURITY_DESCRIPTOR_RELATIVE, Control));

	if (psd == (PISECURITY_DESCRIPTOR)0)
		return (STATUS_INVALID_PARAMETER_1);

	if (pBufferSize == (PULONG)0)
		return (STATUS_INVALID_PARAMETER_2);

	if (!AreControlBitsSet(psd, SE_SELF_RELATIVE))
		return (STATUS_BAD_DESCRIPTOR_FORMAT);

	DoQuerySecurityDescriptor(psd, &owner, &ownerSize, &group, &groupSize, &dacl, &daclSize, &sacl, &saclSize);

	deltaSize = sizeof(SECURITY_DESCRIPTOR) - sizeof(SECURITY_DESCRIPTOR_RELATIVE);
	if (deltaSize == 0) 
	{
		RtlpClearControlBits(psd, SE_SELF_RELATIVE);

		ASSERT(sizeof(psd->Owner) == sizeof(psdr->Owner));
		ASSERT(sizeof(psd->Group) == sizeof(psdr->Group));
		ASSERT(sizeof(psd->Sacl) == sizeof(psdr->Sacl));
		ASSERT(sizeof(psd->Dacl) == sizeof(psdr->Dacl));

		psd->Owner = owner;
		psd->Group = group;
		psd->Sacl = sacl;
		psd->Dacl = dacl;

		return (STATUS_SUCCESS);
	}

#define ULONG_PTR_SDEND( _Adr ) ( (ULONG_PTR)(_Adr) + (ULONG_PTR)(_Adr##Size) )

	ptr = owner > group ? ULONG_PTR_SDEND(owner) : ULONG_PTR_SDEND(group);
	ptr = ptr > (ULONG_PTR)dacl ? ptr : ULONG_PTR_SDEND(dacl);
	ptr = ptr > (ULONG_PTR)sacl ? ptr : ULONG_PTR_SDEND(sacl);

	newBufferSize = sizeof(SECURITY_DESCRIPTOR);
	if (ptr) 
	{
#define ULONG_ROUND_UP( x, y )   ((ULONG)(x) + ((y)-1) & ~((y)-1))

		newBufferSize += ULONG_ROUND_UP((ULONG_PTR)ptr - (ULONG_PTR)(psdr + 1), sizeof(PVOID));
	}

	if (newBufferSize > *pBufferSize) 
	{
		*pBufferSize = newBufferSize;
		return (STATUS_BUFFER_TOO_SMALL);
	}

	if (ptr) 
	{
		RtlMoveMemory((PVOID)(psd + 1), (PVOID)(psdr + 1), newBufferSize - sizeof(SECURITY_DESCRIPTOR));
	}

	RtlpClearControlBits(psd, SE_SELF_RELATIVE);

	psd->Owner = (PSID)(owner ? (ULONG_PTR)owner + deltaSize : 0);
	psd->Group = (PSID)(group ? (ULONG_PTR)group + deltaSize : 0);
	psd->Sacl = (PACL)(sacl ? (ULONG_PTR)sacl + deltaSize : 0);
	psd->Dacl = (PACL)(dacl ? (ULONG_PTR)dacl + deltaSize : 0);

	return (STATUS_SUCCESS);
}

NTSTATUS CreateStandardSCAndACL(OUT PSECURITY_DESCRIPTOR* SecurityDescriptor, OUT PACL* Acl)
{
	PSECURITY_DESCRIPTOR sd = ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR), 'SloV');
	if (!sd)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS ntStatus = RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(sd);
		return ntStatus;
	}

	UCHAR pAdminSidBuffer[2 * sizeof(SID)];
	SID* pAdminSid = (SID*)pAdminSidBuffer;
	pAdminSid->Revision = SID_REVISION;
	pAdminSid->SubAuthorityCount = 2;
	pAdminSid->IdentifierAuthority = (SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY;
	pAdminSid->SubAuthority[0] = SECURITY_BUILTIN_DOMAIN_RID;
	pAdminSid->SubAuthority[1] = DOMAIN_ALIAS_RID_ADMINS;

	UCHAR pSystemSidBuffer[2 * sizeof(SID)];
	SID* pSystemSid = (SID*)pSystemSidBuffer;
	pSystemSid->Revision = SID_REVISION;
	pSystemSid->SubAuthorityCount = 1;
	pSystemSid->IdentifierAuthority = (SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY;
	pSystemSid->SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;

	ULONG ulACLLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(pAdminSid) - sizeof(ULONG) + sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(pSystemSidBuffer) - sizeof(ULONG);
	PACL pACL = ExAllocatePoolWithTag(PagedPool, ulACLLength, 'SloV');
	if (!pACL)
	{
		ExFreePool(sd);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = RtlCreateAcl(pACL, ulACLLength, ACL_REVISION);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pACL);
		ExFreePool(sd);
		return ntStatus;
	}

	ntStatus = RtlAddAccessAllowedAceEx(pACL, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, pAdminSid);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pACL);
		ExFreePool(sd);
		return ntStatus;
	}

	ntStatus = RtlAddAccessAllowedAceEx(pACL, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, pSystemSid);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pACL);
		ExFreePool(sd);
		return ntStatus;
	}

	ntStatus = RtlSetDaclSecurityDescriptor(sd, TRUE, pACL, FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pACL);
		ExFreePool(sd);
		return ntStatus;
	}

	*SecurityDescriptor = sd;
	*Acl = pACL;

	return STATUS_SUCCESS;
}

NTSTATUS GrantAccess(HANDLE hSection, IN PACL StandardAcl)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	ULONG ulNeedSize = 0;

	ntStatus = NtQuerySecurityObject(hSection, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &ulNeedSize);
	if (ntStatus != STATUS_BUFFER_TOO_SMALL)
	{
		DbgPrint("NtQuerySecurityObject fail! Status: %p Need size: %u\n", ntStatus, ulNeedSize);
		return ntStatus;
	}

	PSECURITY_DESCRIPTOR sd = ExAllocatePoolWithTag(PagedPool, ulNeedSize, 'SloV');
	if (!sd)
	{
		DbgPrint("ExAllocatePoolWithTag fail! Status: %p\n", ntStatus);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = NtQuerySecurityObject(hSection, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd, ulNeedSize, &ulNeedSize);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("NtQuerySecurityObject fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return ntStatus;
	}

	PACL pACL = NULL;
	BOOLEAN bDaclPresent, bDaclDefaulted;
	ntStatus = RtlGetDaclSecurityDescriptor(sd, &bDaclPresent, &pACL, &bDaclDefaulted);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlGetDaclSecurityDescriptor fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return ntStatus;
	}

	PSID pSid = NULL;
	BOOLEAN bOwnerDefaulted;
	ntStatus = RtlGetOwnerSecurityDescriptor(sd, &pSid, &bOwnerDefaulted);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlGetOwnerSecurityDescriptor fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return ntStatus;
	}

	UCHAR pAdminSidBuffer[2 * sizeof(SID)];
	SID* pAdminSid = (SID*)pAdminSidBuffer;
	pAdminSid->Revision = SID_REVISION;
	pAdminSid->SubAuthorityCount = 2;
	pAdminSid->IdentifierAuthority = (SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY;
	pAdminSid->SubAuthority[0] = SECURITY_BUILTIN_DOMAIN_RID;
	pAdminSid->SubAuthority[1] = DOMAIN_ALIAS_RID_ADMINS;

	UCHAR pSystemSidBuffer[2 * sizeof(SID)];
	SID* pSystemSid = (SID*)pSystemSidBuffer;
	pSystemSid->Revision = SID_REVISION;
	pSystemSid->SubAuthorityCount = 1;
	pSystemSid->IdentifierAuthority = (SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY;
	pSystemSid->SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;

	ULONG sdLength2 = ulNeedSize;
	ntStatus = RtlSelfRelativeToAbsoluteSD2(sd, &sdLength2);
	if (ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		PSECURITY_DESCRIPTOR sd2 = ExAllocatePoolWithTag(PagedPool, sdLength2, 'SloV');
		if (!sd2)
		{
			ExFreePool(sd);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlCopyMemory(sd2, sd, ulNeedSize);
		ExFreePool(sd);

		sd = sd2;
		ulNeedSize = sdLength2;

		ntStatus = RtlSelfRelativeToAbsoluteSD2(sd, &ulNeedSize);
		if (!NT_SUCCESS(ntStatus))
		{
			ExFreePool(sd);
			return ntStatus;
		}
	}

	ntStatus = RtlSetOwnerSecurityDescriptor(sd, pAdminSid, FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlSetOwnerSecurityDescriptor fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return ntStatus;
	}

	ntStatus = RtlSetDaclSecurityDescriptor(sd, TRUE, StandardAcl, FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlSetDaclSecurityDescriptor fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return ntStatus;
	}

	if (!RtlValidSecurityDescriptor(sd))
	{
		DbgPrint("RtlSetOwnerSecurityDescriptor fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return STATUS_UNSUCCESSFUL;
	}

	ntStatus = NtSetSecurityObject(hSection, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("NtSetSecurityObject fail! Status: %p\n", ntStatus);
		ExFreePool(sd);
		return ntStatus;
	}

	ExFreePool(sd);
	return ntStatus;
}

