// ConsoleApplication.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
// https://github.com/yihleego/handle-tools

#include <iostream>
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <tlhelp32.h>
#include "getopt.h"
#include <string>
#include <vector>

#include "ntstatus.h"


#define NT_SUCCESS(Status)    (((NTSTATUS)(Status)) >= 0)

bool endsWith(const std::string& str, const std::string suffix) {
	if (suffix.length() > str.length()) { return false; }
	return (str.rfind(suffix) == (str.length() - suffix.length()));
}

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG Reserved[22];    // reserved for internal use
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation, // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
	SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
	SystemComPlusPackage, // q; s: ULONG
	SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
	SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
	SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
	SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
	SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
	SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
	SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
	SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation,
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,
	SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
	SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
	SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemCriticalProcessErrorLogInformation,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation, // q: ULONG
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
	SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
	SystemSupportedProcessorArchitectures, // in: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] (Max 5 structs) // NtQuerySystemInformationEx
	SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition,
	SystemKernelDebuggingAllowed, // s: ULONG
	SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // q: ULONG_PTR // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
	SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation,
	SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
	SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
	SystemCodeIntegritySyntheticCacheInformation,
	SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
	SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
	SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
	SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
	SystemSpacesBootInformation, // since 20H2
	SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
	SystemWheaIpmiHardwareInformation,
	SystemDifSetRuleClassInformation,
	SystemDifClearRuleClassInformation,
	SystemDifApplyPluginVerificationOnDriver,
	SystemDifRemovePluginVerificationOnDriver, // 220
	SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
	SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
	SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
	SystemCodeIntegrityAddDynamicStore,
	SystemCodeIntegrityClearDynamicStores,
	SystemDifPoolTrackingInformation,
	SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0, // q: OBJECT_BASIC_INFORMATION
	ObjectNameInformation = 1, // q: OBJECT_NAME_INFORMATION
	ObjectTypeInformation = 2, // q: OBJECT_TYPE_INFORMATION
	ObjectTypesInformation, // q: OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation, // s: void // change object session // (requires SeTcbPrivilege)
	ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID SystemInformation,
	_In_      ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef NTSTATUS(WINAPI* PNtQueryObject)(
	_In_opt_  HANDLE Handle,
	_In_      OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_ PVOID ObjectInformation,
	_In_      ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength);

typedef NTSTATUS(WINAPI* PNtDuplicateObject)(
	_In_      HANDLE SourceProcessHandle,
	_In_      HANDLE SourceHandle,
	_In_opt_  HANDLE TargetProcessHandle,
	_Out_opt_ PHANDLE TargetHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_      ULONG HandleAttributes,
	_In_      ULONG Options
	);

int FindHandles(ULONG pid, LPSTR handleName, BOOL closeHandle, BOOL suffix) {
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
	if (NULL == ntdll) {
		printf("Failed to load 'ntdll.dll'\n");
		return 0;
	}
	PNtQuerySystemInformation pQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	PNtQueryObject pQueryObject = (PNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
	PNtDuplicateObject pDuplicateObject = (PNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
	if (NULL == pQuerySystemInformation || NULL == pQueryObject || NULL == pDuplicateObject) {
		printf("Failed to call 'GetProcAddress()'\n");
		return 0;
	}

	ULONG len = 0x10000;
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		if (len > 0x4000000) {
			return 0;
		}
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);
		status = pQuerySystemInformation(SystemExtendedHandleInformation, pHandleInfo, len, &len);
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status)) {
		printf("Failed to call 'NtQuerySystemInformation()' with error code 0x%X\n", status);
		return 0;
	}

	HANDLE currentProcess = GetCurrentProcess();
	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = pHandleInfo->Handles[i];
		PVOID object = handle.Object;
		HANDLE handleValue = handle.HandleValue;
		HANDLE uniqueProcessId = handle.UniqueProcessId;
		if (NULL != pid && HandleToLong(uniqueProcessId) != pid) {
			continue;
		}
		LPSTR pName = NULL;
		LPSTR pType = NULL;
		HANDLE sourceProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, HandleToULong(uniqueProcessId));
		HANDLE targetHandle = NULL;
		NTSTATUS status = pDuplicateObject(sourceProcess, handleValue, currentProcess, &targetHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
		if (NT_SUCCESS(status)) {
			//printf("Failed to call 'NtDuplicateObject()' with error code 0x%X\n", status);
			POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
			POBJECT_TYPE_INFORMATION pTypeInfo = (POBJECT_TYPE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
			if (NT_SUCCESS(pQueryObject(targetHandle, ObjectNameInformation, pNameInfo, len, NULL))) {
				pName = (LPSTR)GlobalAlloc(GMEM_ZEROINIT, pNameInfo->Name.Length);
				WideCharToMultiByte(CP_ACP, 0, pNameInfo->Name.Buffer, -1, pName, pNameInfo->Name.Length, NULL, NULL);
			}
			if (NT_SUCCESS(pQueryObject(targetHandle, ObjectTypeInformation, pTypeInfo, len, NULL))) {
				pType = (LPSTR)GlobalAlloc(GMEM_ZEROINIT, pTypeInfo->TypeName.Length);
				WideCharToMultiByte(CP_ACP, 0, pTypeInfo->TypeName.Buffer, -1, pType, pTypeInfo->TypeName.Length, NULL, NULL);
			}
		}
		if (NULL != handleName) {
			if (suffix) {
				if (NULL == pName || !endsWith(std::string(pName), std::string(handleName))) {
					continue;
				}
			}
			else {
				if (NULL == pName || 0 != strcmp(pName, handleName)) {
					continue;
				}
			}

			if (TRUE == closeHandle) {
				HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, HandleToLong(uniqueProcessId));
				DuplicateHandle(hProcess, handleValue, 0, 0, 0, 0, DUPLICATE_CLOSE_SOURCE);
				CloseHandle(hProcess);
			}
		}
		printf("PID: %-6d\t", uniqueProcessId);
		printf("Handle: 0x%-3x\t", handleValue);
		printf("Object: 0x%-8X\t", object);
		printf("Type: %-20s\t", NULL != pType ? pType : "<Unknown type>");
		printf("Name: %-30s\t", NULL != pName ? pName : "");
		printf("\n");
	}
	return 1;
}

int DisplayHandles() {
	return FindHandles(NULL, NULL, FALSE, FALSE);
}

int DisplayHandles(ULONG pid) {
	return FindHandles(pid, NULL, FALSE, FALSE);
}

int FindHandle(ULONG pid, LPSTR handleName) {
	return FindHandles(pid, handleName, FALSE, FALSE);
}

int CloseHandle(ULONG pid, LPSTR handleName) {
	return FindHandles(pid, handleName, TRUE, FALSE);
}

HANDLE FindHandleByName(ULONG pid, LPSTR handleName) {
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
	if (NULL == ntdll) {
		printf("Failed to load 'ntdll.dll'\n");
		return 0;
	}
	PNtQuerySystemInformation pQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	PNtQueryObject pQueryObject = (PNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
	PNtDuplicateObject pDuplicateObject = (PNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
	if (NULL == pQuerySystemInformation || NULL == pQueryObject || NULL == pDuplicateObject) {
		printf("Failed to call 'GetProcAddress()'\n");
		return 0;
	}

	ULONG len = 0x10000;
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		if (len > 0x4000000) {
			return 0;
		}
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);
		status = pQuerySystemInformation(SystemExtendedHandleInformation, pHandleInfo, len, &len);
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status)) {
		printf("Failed to call 'NtQuerySystemInformation()' with error code 0x%X\n", status);
		return 0;
	}

	HANDLE currentProcess = GetCurrentProcess();
	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = pHandleInfo->Handles[i];
		PVOID object = handle.Object;
		HANDLE handleValue = handle.HandleValue;
		HANDLE uniqueProcessId = handle.UniqueProcessId;
		if (NULL != pid && HandleToLong(uniqueProcessId) != pid) {
			continue;
		}
		LPSTR pName = NULL;
		LPSTR pType = NULL;
		HANDLE sourceProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, HandleToULong(uniqueProcessId));
		HANDLE targetHandle = NULL;
		NTSTATUS status = pDuplicateObject(sourceProcess, handleValue, currentProcess, &targetHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
		if (NT_SUCCESS(status)) {
			//printf("Failed to call 'NtDuplicateObject()' with error code 0x%X\n", status);
			POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
			POBJECT_TYPE_INFORMATION pTypeInfo = (POBJECT_TYPE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
			if (NT_SUCCESS(pQueryObject(targetHandle, ObjectNameInformation, pNameInfo, len, NULL))) {
				pName = (LPSTR)GlobalAlloc(GMEM_ZEROINIT, pNameInfo->Name.Length);
				WideCharToMultiByte(CP_ACP, 0, pNameInfo->Name.Buffer, -1, pName, pNameInfo->Name.Length, NULL, NULL);
			}
			if (NT_SUCCESS(pQueryObject(targetHandle, ObjectTypeInformation, pTypeInfo, len, NULL))) {
				pType = (LPSTR)GlobalAlloc(GMEM_ZEROINIT, pTypeInfo->TypeName.Length);
				WideCharToMultiByte(CP_ACP, 0, pTypeInfo->TypeName.Buffer, -1, pType, pTypeInfo->TypeName.Length, NULL, NULL);
			}
		}
		if (NULL != handleName) {

			if (NULL == pName || 0 != strcmp(pName, handleName)) {
				continue;
			}
			return handleValue;
		}

	}
}


namespace {

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE handle) : handle_(handle) {}
    ~ScopedHandle() {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            CloseHandle(handle_);
            SetLastError(error);
        }
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE get() const { return handle_; }
    explicit operator bool() const {
        return handle_ && handle_ != INVALID_HANDLE_VALUE;
    }
private:
    HANDLE handle_;
};

int ReportError(const char* operation, DWORD error = GetLastError()) {
    fprintf(stderr, "%s failed (Windows error %lu).\n", operation, error);
    return 0;
}

// Snapshots can race module loading; retry only the documented transient error.
HANDLE ModuleSnapshot(DWORD pid) {
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 8; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
    }
    return snapshot;
}

bool SameArchitecture(HANDLE target) {
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    auto query = reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    if (query) {
        USHORT current_machine = 0, current_native = 0, target_machine = 0, target_native = 0;
        if (!query(GetCurrentProcess(), &current_machine, &current_native) ||
            !query(target, &target_machine, &target_native)) {
            ReportError("IsWow64Process2");
            return false;
        }
        if (current_machine == IMAGE_FILE_MACHINE_UNKNOWN) current_machine = current_native;
        if (target_machine == IMAGE_FILE_MACHINE_UNKNOWN) target_machine = target_native;
        if (current_machine == target_machine) return true;
    } else {
        BOOL current_wow64 = FALSE, target_wow64 = FALSE;
        if (!IsWow64Process(GetCurrentProcess(), &current_wow64) ||
            !IsWow64Process(target, &target_wow64)) {
            ReportError("IsWow64Process");
            return false;
        }
        if (current_wow64 == target_wow64) return true;
    }
    fprintf(stderr, "Injector and target architectures differ; cross-architecture injection is unsupported.\n");
    return false;
}

} // namespace

std::wstring Utf8ToUnicode(const char* buffer) {
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buffer, -1, nullptr, 0);
    if (!size) return {};
    std::wstring result(size, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buffer, -1, &result[0], size)) return {};
    result.resize(size - 1);
    return result;
}

DWORD GetPIDForProcess(const wchar_t* process) {
    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        ReportError("CreateToolhelp32Snapshot(processes)");
        return 0;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    for (BOOL found = Process32FirstW(snapshot.get(), &entry); found;
         found = Process32NextW(snapshot.get(), &entry)) {
        if (_wcsicmp(entry.szExeFile, process) == 0) return entry.th32ProcessID;
    }
    fprintf(stderr, "Target process was not found.\n");
    return 0;
}

HMODULE GetDLLHandle(const wchar_t* name_or_path, DWORD pid, bool full_path = false) {
    if (!pid) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    ScopedHandle snapshot(ModuleSnapshot(pid));
    if (!snapshot) {
        ReportError("CreateToolhelp32Snapshot(modules)");
        return nullptr;
    }
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    for (BOOL found = Module32FirstW(snapshot.get(), &entry); found;
         found = Module32NextW(snapshot.get(), &entry)) {
        if (_wcsicmp(full_path ? entry.szExePath : entry.szModule, name_or_path) == 0) {
            return entry.hModule;
        }
    }
    if (GetLastError() == ERROR_NO_MORE_FILES) {
        SetLastError(ERROR_MOD_NOT_FOUND);
    }
    return nullptr;
}

BOOL EnableDebugPrivilege() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw_token)) return FALSE;
    ScopedHandle token(raw_token);
    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) return FALSE;
    SetLastError(ERROR_SUCCESS);
    return AdjustTokenPrivileges(token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr) &&
           GetLastError() == ERROR_SUCCESS;
}

HANDLE OpenInjectionTarget(DWORD pid) {
    constexpr DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE process = OpenProcess(access, FALSE, pid);
    // Same-user targets normally need no debug privilege.
    if (!process && GetLastError() == ERROR_ACCESS_DENIED && EnableDebugPrivilege()) {
        process = OpenProcess(access, FALSE, pid);
    }
    return process;
}

// Resolve the actual owning module (kernel32 exports may forward to KernelBase),
// then apply its RVA to the target's base instead of assuming identical ASLR bases.
LPTHREAD_START_ROUTINE RemoteSystemFunction(DWORD pid, const char* name) {
    auto function = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name);
    if (!function) return nullptr;
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(function), &owner)) return nullptr;
    wchar_t owner_path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(owner, owner_path, MAX_PATH);
    if (!length || length == MAX_PATH) return nullptr;
    const wchar_t* owner_name = wcsrchr(owner_path, L'\\');
    const HMODULE remote_owner = GetDLLHandle(owner_name ? owner_name + 1 : owner_path, pid);
    if (!remote_owner) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return nullptr;
    }
    const auto offset = reinterpret_cast<ULONG_PTR>(function) - reinterpret_cast<ULONG_PTR>(owner);
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<ULONG_PTR>(remote_owner) + offset);
}

int InjectDllByPid(unsigned int pid, const wchar_t* dll_path) {
    if (!pid || !dll_path || !*dll_path) return ReportError("Injection arguments", ERROR_INVALID_PARAMETER);
    const DWORD needed = GetFullPathNameW(dll_path, 0, nullptr, nullptr);
    if (!needed) return ReportError("GetFullPathNameW");
    std::wstring full_path(needed, L'\0');
    const DWORD length = GetFullPathNameW(dll_path, needed, &full_path[0], nullptr);
    if (!length || length >= needed) return ReportError("GetFullPathNameW");
    full_path.resize(length);
    const DWORD attributes = GetFileAttributesW(full_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return ReportError("DLL file");
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) return ReportError("DLL file", ERROR_DIRECTORY);

    ScopedHandle process(OpenInjectionTarget(pid));
    if (!process) return ReportError("OpenProcess");
    if (!SameArchitecture(process.get())) return 0;
    const auto load_library = RemoteSystemFunction(pid, "LoadLibraryW");
    if (!load_library) return ReportError("Resolve remote LoadLibraryW");

    const SIZE_T path_size = (full_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote_path = VirtualAllocEx(process.get(), nullptr, path_size,
                                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_path) return ReportError("VirtualAllocEx");
    SIZE_T written = 0;
    if (!WriteProcessMemory(process.get(), remote_path, full_path.c_str(), path_size, &written) || written != path_size) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process.get(), remote_path, 0, MEM_RELEASE);
        return ReportError("WriteProcessMemory", error);
    }
    ScopedHandle thread(CreateRemoteThread(process.get(), nullptr, 0, load_library, remote_path, 0, nullptr));
    if (!thread) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process.get(), remote_path, 0, MEM_RELEASE);
        return ReportError("CreateRemoteThread", error);
    }
    const DWORD wait_result = WaitForSingleObject(thread.get(), 30000);
    if (wait_result != WAIT_OBJECT_0) {
        // The loader may still be reading the argument. Do not free live memory
        // or terminate an arbitrary loader thread on timeout.
        fprintf(stderr, "Remote loader did not finish; its path allocation is retained until the target exits.\n");
        return ReportError("WaitForSingleObject", wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
    }
    DWORD loader_result = 0;
    const BOOL got_result = GetExitCodeThread(thread.get(), &loader_result);
    const DWORD result_error = GetLastError();
    const BOOL freed = VirtualFreeEx(process.get(), remote_path, 0, MEM_RELEASE);
    if (!freed) return ReportError("VirtualFreeEx");
    if (!got_result) return ReportError("GetExitCodeThread", result_error);

    // A thread exit code is only a DWORD, whereas HMODULE is 64 bits here.
    // Verify the full module path rather than using a truncated handle as proof.
    if (!GetDLLHandle(full_path.c_str(), pid, true)) {
        fprintf(stderr, "DLL was not loaded (remote thread result 0x%08lX). It may have been rejected by DllMain.\n", loader_result);
        return 0;
    }
    printf("DLL loaded in process %u. API readiness has not been verified.\n", pid);
    return 1;
}

int InjectDll(const wchar_t* process_name, const wchar_t* dll_path) {
    const DWORD pid = GetPIDForProcess(process_name);
    return pid ? InjectDllByPid(pid, dll_path) : 0;
}

int UnInjectDll(const wchar_t* process_name, const wchar_t* dll_name) {
    const DWORD pid = GetPIDForProcess(process_name);
    if (!pid) return 0;
    ScopedHandle process(OpenInjectionTarget(pid));
    if (!process) return ReportError("OpenProcess");
    if (!SameArchitecture(process.get())) return 0;
    const auto free_library = RemoteSystemFunction(pid, "FreeLibrary");
    if (!free_library) return ReportError("Resolve remote FreeLibrary");
    const HMODULE module = GetDLLHandle(dll_name, pid);
    if (!module) return ReportError("Target DLL", ERROR_MOD_NOT_FOUND);
    ScopedHandle thread(CreateRemoteThread(process.get(), nullptr, 0, free_library, module, 0, nullptr));
    if (!thread) return ReportError("CreateRemoteThread");
    const DWORD wait_result = WaitForSingleObject(thread.get(), 30000);
    if (wait_result != WAIT_OBJECT_0) return ReportError("WaitForSingleObject", wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
    DWORD result = 0;
    if (!GetExitCodeThread(thread.get(), &result)) return ReportError("GetExitCodeThread");
    if (!result) return ReportError("Remote FreeLibrary", ERROR_DLL_INIT_FAILED);
    if (GetDLLHandle(dll_name, pid)) {
        fprintf(stderr, "DLL remains loaded (pinned or still referenced). Exit the target normally to unload it.\n");
        return 0;
    }
    return GetLastError() == ERROR_MOD_NOT_FOUND;
}

bool ParsePid(const char* argument, DWORD* pid) {
    if (!argument || !*argument) return false;
    unsigned long long value = 0;
    for (const char* digit = argument; *digit; ++digit) {
        if (*digit < '0' || *digit > '9') return false;
        value = value * 10 + (*digit - '0');
        if (value > MAXDWORD) return false;
    }
    if (!value) return false;
    *pid = static_cast<DWORD>(value);
    return true;
}

void PrintHelp(const char* program) {
    printf("Usage: %s -i <process name> -p <DLL path>\n", program);
    printf("       %s -I <pid> -p <DLL path>\n", program);
    printf("       %s -u <process name> -d <DLL name>\n", program);
    printf("       %s -m <pid>\n", program);
    printf("  -h  Print help.\n");
    printf("  -P  Unsupported legacy HTTP-start option; configure the DLL normally.\n");
    printf("Loading a DLL does not verify support for the target WeChat version.\n");
}

int RunInjector(int argc, char** argv) {
    std::string inject_program, unload_program, dll_path, dll_name;
    DWORD mutex_pid = 0, inject_pid = 0;
    bool legacy_http = false;
    int option;
    while ((option = getopt(argc, argv, "i:p:u:d:m:P:I:h")) != -1) {
        switch (option) {
        case 'i': inject_program = optarg; break;
        case 'p': dll_path = optarg; break;
        case 'u': unload_program = optarg; break;
        case 'd': dll_name = optarg; break;
        case 'm':
            if (!ParsePid(optarg, &mutex_pid)) return ReportError("PID", ERROR_INVALID_PARAMETER), 2;
            break;
        case 'I':
            if (!ParsePid(optarg, &inject_pid)) return ReportError("PID", ERROR_INVALID_PARAMETER), 2;
            break;
        case 'P': legacy_http = true; break;
        case 'h': PrintHelp(argv[0]); return 0;
        default: PrintHelp(argv[0]); return 2;
        }
    }
    // Reject before opening a target or changing any process state, including -P 0.
    if (legacy_http) {
        fprintf(stderr, "-P is unsupported: the removed legacy routine used x86 shellcode and truncated x64 addresses.\n");
        return 2;
    }
    const bool injecting = inject_pid != 0 || !inject_program.empty();
    const bool unloading = !unload_program.empty();
    if (optind != argc || (inject_pid && !inject_program.empty()) || (injecting && unloading) ||
        (injecting && dll_path.empty()) || (unloading && dll_name.empty()) ||
        (!injecting && !dll_path.empty()) || (!unloading && !dll_name.empty()) ||
        (!injecting && !unloading && !mutex_pid)) {
        PrintHelp(argv[0]);
        return 2;
    }
    const std::wstring wide_program = Utf8ToUnicode(injecting ? inject_program.c_str() : unload_program.c_str());
    const std::wstring wide_dll = Utf8ToUnicode(injecting ? dll_path.c_str() : dll_name.c_str());
    if ((injecting || unloading) && (wide_dll.empty() || (!inject_pid && wide_program.empty()))) {
        fprintf(stderr, "Process and DLL arguments must be valid UTF-8.\n");
        return 2;
    }
    if (mutex_pid) {
        FindHandles(mutex_pid, (LPSTR)"_WeChat_App_Instance_Identity_Mutex_Name", TRUE, TRUE);
    }
    if (injecting) {
        const int result = inject_pid ? InjectDllByPid(inject_pid, wide_dll.c_str()) :
            InjectDll(wide_program.c_str(), wide_dll.c_str());
        return result ? 0 : 1;
    }
    if (unloading) return UnInjectDll(wide_program.c_str(), wide_dll.c_str()) ? 0 : 1;
    return 0;
}

int wmain(int argc, wchar_t** wide_argv) {
    std::vector<std::string> arguments;
    arguments.reserve(argc);
    for (int index = 0; index < argc; ++index) {
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            wide_argv[index], -1, nullptr, 0, nullptr, nullptr);
        if (!size) return ReportError("Command-line encoding"), 2;
        std::string argument(size, '\0');
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_argv[index],
                -1, &argument[0], size, nullptr, nullptr)) {
            return ReportError("Command-line encoding"), 2;
        }
        argument.resize(size - 1);
        arguments.push_back(std::move(argument));
    }
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(&argument[0]);
    argv.push_back(nullptr);
    return RunInjector(argc, argv.data());
}
