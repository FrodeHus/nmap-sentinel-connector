from typing import List


class Target:
    def __init__(
        self,
        name: str,
        target: str,
        quick_scan: bool = True,
        send_to_analytics: bool = True,
        output_file: str = None,
    ) -> None:
        """Represents a target to scan

        Args:
            name (str): The name of the target (for display only)
            target (str): The single IP or network address range to scan
            quick_scan (bool, optional): Run a quick scan - disables full port and service type discovery. Defaults to True.
            send_to_analytics (bool, optional): Send results to Log Analytics Workspace. Defaults to True.
            output_file (str, optional): Save scan result to the specified JSON-file. Defaults to None.
        """
        self.name = name
        self.target = target
        self.quick_scan = quick_scan
        self.send_to_analytics = send_to_analytics
        self.output_file = output_file

        if not self.target:
            raise Exception("Must specify target")


class LogAnalyticsConfig:
    def __init__(
        self, workspace_id: str, shared_access_key: str, log_name: str = "NetworkAudit"
    ) -> None:
        """Configuration for sending results to Log Analytics Workspace

        Args:
            workspace_id (str): The workspace ID
            shared_access_key (str): Shared access key used to authenticate to Log Analytics Workspace
            log_name (str, optional): The custom log name where results should be saved. Defaults to "NetworkAudit".
        """
        self.workspace_id = workspace_id
        self.shared_access_key = shared_access_key
        self.log_name = log_name


class ConfigFile:
    def __init__(
        self,
        targets: List[Target],
        log_analytics_config: LogAnalyticsConfig = None,
        schedule: int = None,
    ) -> None:
        """Represents a network audit configuration

        Args:
            targets (Targets): List of targets to audit
            log_analytics_config (LogAnalyticsConfig, optional): Log Analytics Workspace configuration. Defaults to None.
            schedule (int, optional): Run every <num> minutes. Defaults to None.
        """
        self.targets: List[Target] = targets
        self.log_analytics_config = log_analytics_config
        self.schedule = schedule

    @staticmethod
    def from_dict(config_data: dict):
        targets = []
        for target_data in config_data["targets"]:
            name = target_data["name"] if "name" in target_data else "Not specified"
            target = target_data["target"] if "target" in target_data else None
            quick_scan = (
                target_data["quickScan"] if "quickScan" in target_data else True
            )
            output_file = (
                target_data["outputFile"] if "outputFile" in target_data else None
            )
            send_to_analytics = (
                target_data["sendToLogAnalytics"]
                if "sendToLogAnalytics" in target_data
                else True
            )
            targets.append(
                Target(
                    name=name,
                    target=target,
                    quick_scan=quick_scan,
                    send_to_analytics=send_to_analytics,
                    output_file=output_file,
                )
            )

        analytics_config = config_data["logAnalytics"]
        workspace_id = (
            analytics_config["workspaceId"]
            if "workspaceId" in analytics_config
            else None
        )
        shared_access_key = (
            analytics_config["sharedAccessKey"]
            if "sharedAccessKey" in analytics_config
            else None
        )
        log_name = (
            analytics_config["logName"]
            if "logName" in analytics_config
            else "NetworkAudit"
        )

        schedule = config_data["runEvery"] if "runEvery" in config_data else None
        return ConfigFile(
            targets,
            LogAnalyticsConfig(
                workspace_id=workspace_id,
                shared_access_key=shared_access_key,
                log_name=log_name,
            ),
            schedule=schedule,
        )
