import re
from collections import Counter
from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Set
from uuid import UUID

from sigma.rule import SigmaRule, SigmaLogSource

from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

sigmahq_logsource_prefix: Dict[SigmaLogSource, str] = {
    SigmaLogSource("create_remote_thread", "windows", None): "create_remote_thread_",
    SigmaLogSource("create_stream_hash", "windows", None): "create_stream_hash_",
    SigmaLogSource("dns", None, None): "net_dns_",
    SigmaLogSource("dns_query", "windows", None): "dns_query_win_",
    SigmaLogSource("driver_load", "windows", None): "driver_load_win_",
    SigmaLogSource("file_access", "windows", None): "file_access_win_",
    SigmaLogSource("file_change", "windows", None): "file_change_win_",
    SigmaLogSource("file_delete", "windows", None): "file_delete_win_",
    SigmaLogSource("file_event", "linux", None): "file_event_lnx_",
    SigmaLogSource("file_event", "macos", None): "file_event_macos_",
    SigmaLogSource("file_event", "windows", None): "file_event_win_",
    SigmaLogSource("file_rename", "windows", None): "file_rename_win_",
    SigmaLogSource("firewall", None, None): "net_firewall_",
    SigmaLogSource("image_load", "windows", None): "image_load_",
    SigmaLogSource("network_connection", "linux", None): "net_connection_lnx_",
    SigmaLogSource("network_connection", "macos", None): "net_connection_macos_",
    SigmaLogSource("network_connection", "windows", None): "net_connection_win_",
    SigmaLogSource("pipe_created", "windows", None): "pipe_created_",
    SigmaLogSource("process_access", "windows", None): "proc_access_win_",
    SigmaLogSource("process_creation", "linux", None): "proc_creation_lnx_",
    SigmaLogSource("process_creation", "macos", None): "proc_creation_macos_",
    SigmaLogSource("process_creation", "windows", None): "proc_creation_win_",
    SigmaLogSource("process_tampering", "windows", None): "proc_tampering_",
    SigmaLogSource("ps_classic_provider_start", "windows", None): "posh_pc_",
    SigmaLogSource("ps_classic_start", "windows", None): "posh_pc_",
    SigmaLogSource("ps_module", "windows", None): "posh_pm_",
    SigmaLogSource("ps_script", "windows", None): "posh_ps_",
    SigmaLogSource("raw_access_thread", "windows", None): "raw_access_thread_",
    SigmaLogSource("registry_add", "windows", None): "registry_add_",
    SigmaLogSource("registry_delete", "windows", None): "registry_delete_",
    SigmaLogSource("registry_event", "windows", None): "registry_event_",
    SigmaLogSource("registry_rename", "windows", None): "registry_rename_",
    SigmaLogSource("registry_set", "windows", None): "registry_set_",
    SigmaLogSource("sysmon_error", "windows", None): "sysmon_",
    SigmaLogSource("sysmon_status", "windows", None): "sysmon_",
    SigmaLogSource("wmi_event", "windows", None): "sysmon_wmi_",
    SigmaLogSource("webserver", None, None): "web_",
    SigmaLogSource(None, "azure", "pim"): "azure_pim_",
    SigmaLogSource(None, "linux", "auditd"): "lnx_auditd_",
    SigmaLogSource(None, "linux", "modsecurity"): "modsec_",
    SigmaLogSource(None, "windows", "applocker"): "win_applocker_",
    SigmaLogSource(None, "windows", "bitlocker"): "win_bitlocker_",
    SigmaLogSource(None, "windows", "bits-client"): "win_bits_client_",
    SigmaLogSource(None, "windows", "capi2"): "win_capi2_",
    SigmaLogSource(
        None, "windows", "certificateservicesclient-lifecycle-system"
    ): "win_certificateservicesclient_lifecycle_system_",
    SigmaLogSource(None, "windows", "codeintegrity-operational"): "win_codeintegrity_",
    SigmaLogSource(None, "windows", "diagnosis-scripted"): "win_diagnosis_scripted_",
    SigmaLogSource(None, "windows", "dns-server-analytic"): "win_dns_analytic_",
    SigmaLogSource(None, "windows", "firewall-as"): "win_firewall_as_",
    SigmaLogSource(None, "windows", "msexchange-management"): "win_exchange_",
    SigmaLogSource(None, "windows", "powershell-classic"): "posh_pc_",
    SigmaLogSource(None, "windows", "security"): "win_security_",
    SigmaLogSource(None, "windows", "sysmon"): "sysmon_",
    SigmaLogSource(None, "windows", "system"): "win_system_",
    SigmaLogSource(None, "windows", "taskscheduler"): "win_taskscheduler_",
    SigmaLogSource(
        None, "windows", "terminalservices-localsessionmanager"
    ): "win_terminalservices_",
    SigmaLogSource(None, "windows", "windefend"): "win_defender_",
    SigmaLogSource(None, "windows", "wmi"): "win_wmi_",
}

sigmahq_product_prefix: Dict[str, str] = {
    "aws": "aws_",
    "azure": "azure_",
    "gcp": "gcp_",
    "github": "github_",
    "linux": "lnx_",
    "m365": "microsoft365_",
    "macos": "macos_",
    "okta": "okta_",
    "onelogin": "onelogin_",
    "windows": "win_",
}


@dataclass
class SigmahqFilenameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ standard"
    severity: ClassVar[
        SigmaValidationIssueSeverity
    ] = SigmaValidationIssueSeverity.MEDIUM
    filename: str


class SigmahqFilenameValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ standard."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [SigmahqFilenameIssue(rule, filename)]
        return []


@dataclass
class SigmahqFilenamePrefixIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ Prefix standard"
    severity: ClassVar[
        SigmaValidationIssueSeverity
    ] = SigmaValidationIssueSeverity.MEDIUM
    filename: str
    logsource: SigmaLogSource


class SigmahqFilenamePrefixValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ prefix standard."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            logsource = rule.logsource

            if logsource in sigmahq_logsource_prefix:
                if not filename.startswith(sigmahq_logsource_prefix[logsource]):
                    return [SigmahqFilenamePrefixIssue(rule, filename, logsource)]
            else:
                if (
                    logsource.product in sigmahq_product_prefix
                    and not filename.startswith(
                        sigmahq_product_prefix[logsource.product]
                    )
                ):
                    return [SigmahqFilenamePrefixIssue(rule, filename, logsource)]
        return []
