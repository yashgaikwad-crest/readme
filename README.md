Connects to Illumio Core APIs to perform investigative and restorative actions.
This integration was integrated and tested with version 1.1.1 of IllumioCore

## Configure Illumio Core on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Illumio Core.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The URL this integration should connect to. | True |
    | Port | The port number to establish the connection. | True |
    | API Key Username | The API user for authentication. | True |
    | API Secret | The API Key required to authenticate to the service. | True |
    | Organization ID | The organization ID to use when calling org-dependent APIs. | True |
    | Trust any certificate (not secure) | Indicates whether to allow connections without verifying SSL certificate's validity. | False |
    | Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### illumio-ip-lists-get
***
Retrieves the list of IPs based on the query parameters.


#### Base Command

`illumio-ip-lists-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Description of IP list to return. Support partial matches. | Optional | 
| fqdn | IP lists matching fqdn. Supports partial matches. | Optional | 
| ip_address | IP address matching IP list(s) to return. Supports partial matches. | Optional | 
| max_results | Maximum number of IP Lists to return.The value must be positive integer. High value will result in performance issue.<br/>Note: 2500 is the optimum value. Default is 500. | Optional | 
| name | Name of IP list(s) to return. Supports partial matches. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.IPLists.href | String | URI of the IP list. | 
| Illumio.IPLists.description | String | Description of IP list. | 
| Illumio.IPLists.external_data_set | String | External data set identifier. | 
| Illumio.IPLists.external_data_reference | String | External data reference identifier. | 
| Illumio.IPLists.created_at | Date | Time stamp when this IP list was first created. | 
| Illumio.IPLists.updated_at | Date | Time stamp when this IP List was last updated. | 
| Illumio.IPLists.deleted_at | Date | Time stamp when this IP List was deleted. | 
| Illumio.IPLists.created_by.href | String | User who originally created this IP List. | 
| Illumio.IPLists.updated_by.href | String | User who last updated this IP List. | 
| Illumio.IPLists.deleted_by.href | String | User who has deleted this IP List. | 
| Illumio.IPLists.name | String | Name \(must be unique\). | 
| Illumio.IPLists.ip_ranges.description | String | Description of given IP range. | 
| Illumio.IPLists.ip_ranges.from_ip | String | IP address or a low end of IP range. Might be specified with CIDR notation. | 
| Illumio.IPLists.ip_ranges.to_ip | String | High end of an IP range. | 
| Illumio.IPLists.ip_ranges.exclusion | Boolean | Whether this IP address is an exclusion. Exclusions must be a strict subset of inclusive IP addresses. | 
| Illumio.IPLists.fqdns.fqdn | String | Fully qualified domain name. | 
| Illumio.IPLists.fqdns.description | String | Description of FQDN. | 

#### Command example
```!illumio-ip-lists-get max_results=2```
#### Context Example
```json
{
    "Illumio": {
        "IPLists": [
            {
                "created_at": "2019-04-05T19:58:39.545Z",
                "created_by": {
                    "href": "/users/0"
                },
                "href": "/orgs/1/sec_policy/draft/ip_lists/1",
                "ip_ranges": [
                    {
                        "exclusion": false,
                        "from_ip": "0.0.0.0/0"
                    },
                    {
                        "exclusion": false,
                        "from_ip": "::/0"
                    }
                ],
                "name": "Any (0.0.0.0/0 and ::/0)",
                "updated_at": "2019-04-05T19:58:39.552Z",
                "updated_by": {
                    "href": "/users/0"
                }
            },
            {
                "created_at": "2022-08-17T07:31:45.037Z",
                "created_by": {
                    "href": "/users/65"
                },
                "description": "",
                "href": "/orgs/1/sec_policy/draft/ip_lists/977",
                "ip_ranges": [
                    {
                        "exclusion": false,
                        "from_ip": "0.0.0.0"
                    }
                ],
                "name": "test-xyz",
                "updated_at": "2022-08-17T07:31:45.040Z",
                "updated_by": {
                    "href": "/users/65"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### IP Lists:
>|IP List HREF|Name|Created At|Updated At|IP Ranges|
>|---|---|---|---|---|
>| /orgs/1/sec_policy/draft/ip_lists/1 | Any (0.0.0.0/0 and ::/0) | 05 Apr 2019, 07:58 PM | 05 Apr 2019, 07:58 PM | 0.0.0.0/0, ::/0 |
>| /orgs/1/sec_policy/draft/ip_lists/977 | test-xyz | 17 Aug 2022, 07:31 AM | 17 Aug 2022, 07:31 AM | 0.0.0.0 |


### illumio-enforcement-boundary-create
***
Creates an enforcement boundary for a particular port/protocol. After completion of this command, provisioning will be done using the "illumio-object-provision" command.


#### Base Command

`illumio-enforcement-boundary-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Enforcement boundary name. | Required | 
| port | Port number. | Required | 
| protocol | Communication protocol. Possible values are: TCP, UDP. Default is TCP. | Optional | 
| providers | List of HREFs of entities to be used as providers for the rule, or "ams" for all workloads. Supports comma separated values. | Required | 
| consumers | List of HREFs of entities to be used as consumers for the rule, or "ams" for all workloads. Supports comma separated values. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.EnforcementBoundary.href | String | Enforcement boundary label URI. | 
| Illumio.EnforcementBoundary.created_at | Date | Enforcement boundary creation time. | 
| Illumio.EnforcementBoundary.updated_at | Date | Enforcement boundary updated time. | 
| Illumio.EnforcementBoundary.deleted_at | Date | Enforcement boundary deleted time. | 
| Illumio.EnforcementBoundary.created_by.href | String | URI of the user who has created the enforcement boundary. | 
| Illumio.EnforcementBoundary.updated_by.href | String | URI of the user who has updated the enforcement boundary. | 
| Illumio.EnforcementBoundary.deleted_by.href | String | URI of the user who has deleted the enforcement boundary. | 
| Illumio.EnforcementBoundary.update_type | String | Type of the modification done on the enforcement boundary. | 
| Illumio.EnforcementBoundary.name | String | Name of the enforcement boundary. | 
| Illumio.EnforcementBoundary.providers.actors | String | All managed workloads \('ams'\). | 
| Illumio.EnforcementBoundary.providers.label.href | String | URI of the provider label. | 
| Illumio.EnforcementBoundary.providers.label_group.href | String | URI of the provider label group. | 
| Illumio.EnforcementBoundary.providers.ip_list.href | String | Providers IP list label URI. | 
| Illumio.EnforcementBoundary.consumers.actors | String | All managed workloads \('ams'\). | 
| Illumio.EnforcementBoundary.consumers.label.href | String | URI of the consumer label. | 
| Illumio.EnforcementBoundary.consumers.label_group.href | String | URI of the consumer label group. | 
| Illumio.EnforcementBoundary.consumers.ip_list.href | String | Consumers IP list label URI. | 
| Illumio.EnforcementBoundary.ingress_service.port | Number | Port of the ingress services. | 
| Illumio.EnforcementBoundary.ingress_services.proto | Number | Protocol of the ingress services. | 
| Illumio.EnforcementBoundary.ingress_services.href | String | URI of the ingress service. | 
| Illumio.EnforcementBoundary.caps | Unknown | Array of permissions for the entity to the current user - an empty array implies read only access. | 

#### Command example
```!illumio-enforcement-boundary-create consumers=ams providers=ams name=trail-service-test-103 port=8443```
#### Context Example
```json
{
    "Illumio": {
        "EnforcementBoundary": {
            "consumers": [
                {
                    "actors": "ams"
                }
            ],
            "ingress_services": [
                {
                    "port": 8443,
                    "proto": 6
                }
            ],
            "name": "trail-service-test-103",
            "providers": [
                {
                    "actors": "ams"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Enforcement Boundary:
>
>|Name|Ingress Services|
>|---|---|
>| trail-service-test-103 | 8443-TCP |


### illumio-workloads-list
***
Retrieves the list of workloads based on the provided filters.


#### Base Command

`illumio-workloads-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Maximum number of workloads to return in the result set. The value must be positive integer. High value will result in performance issue.<br/>Note: 2500 is the optimum value. Default is 500. | Optional | 
| name | Workload name. | Optional | 
| hostname | Workload hostname. | Optional | 
| ip_address | Workload IP address. Supports partial matches. | Optional | 
| online | True to return online workloads, false to return offline workloads. Leave empty to return both. Possible values are: true, false. | Optional | 
| managed | True to return managed workloads, false to return unmanaged workloads. Leave empty to return both. Possible values are: true, false. | Optional | 
| labels | Workload labels. | Optional | 
| enforcement_mode | Workload enforcement mode. Possible values are: visibility_only, full, idle, selective. | Optional | 
| visibility_level | Workload visibility level. Possible values are: flow_full_detail, flow_summary, flow_drops, flow_off, enhanced_data_collection. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.Workloads.href | String | URI of workload. | 
| Illumio.Workloads.deleted | Boolean | Whether this workload has been deleted or not. | 
| Illumio.Workloads.delete_type | String | Workload deletion type. | 
| Illumio.Workloads.name | String | Interface name. | 
| Illumio.Workloads.description | String | The description of this workload. | 
| Illumio.Workloads.managed | Boolean | True if the workload is managed, else false. | 
| Illumio.Workloads.hostname | String | The hostname of this workload. | 
| Illumio.Workloads.service_principal_name | String | The Kerberos Service Principal Name \(SPN\). | 
| Illumio.Workloads.agent_to_pce_certificate_authentication_id | String | PKI Certificate identifier to be used by the PCE for authenticating the VEN. | 
| Illumio.Workloads.distinguished_name | String | X.509 Subject distinguished name. | 
| Illumio.Workloads.public_ip | String | The public IP address of the server. | 
| Illumio.Workloads.external_data_set | String | External data set identifier. | 
| Illumio.Workloads.external_data_reference | String | External data reference identifier. | 
| Illumio.Workloads.interfaces.name | String | Interface name. | 
| Illumio.Workloads.interfaces.link_state | String | Link state. | 
| Illumio.Workloads.interfaces.address | String | The IP address to assign to this interface. | 
| Illumio.Workloads.interfaces.cidr_block | Number | The number of bits in the subnet /24 is 255.255.255.0. | 
| Illumio.Workloads.interfaces.default_gateway_address | String | The IP address of the default gateway. | 
| Illumio.Workloads.interfaces.network.href | String | URI of the network. | 
| Illumio.Workloads.interfaces.network_detection_mode | String | Network detection mode. | 
| Illumio.Workloads.interfaces.friendly_name | String | User-friendly name for interface. | 
| Illumio.Workloads.service_provider | String | Service provider. | 
| Illumio.Workloads.data_center | String | Data center. | 
| Illumio.Workloads.data_center_zone | String | Data center zone. | 
| Illumio.Workloads.os_id | String | Our OS identifier. | 
| Illumio.Workloads.os_detail | String | Additional OS details - just displayed to the end user. | 
| Illumio.Workloads.online | Boolean | If this workload is online. | 
| Illumio.Workloads.firewall_coexistence.illumio_primary | Boolean | Illumio is the primary firewall if set to true. | 
| Illumio.Workloads.containers_inherit_host_policy | Boolean | This workload will apply the policy it receives both to itself and the containers hosted by it. | 
| Illumio.Workloads.blocked_connection_action | String | Firewall action for blocked connections. | 
| Illumio.Workloads.labels.href | String | URI of this label. | 
| Illumio.Workloads.labels.deleted | Boolean | Assigned labels. | 
| Illumio.Workloads.labels.key | String | Key in key-value pair. | 
| Illumio.Workloads.labels.value | String | Value in key-value pair. | 
| Illumio.Workloads.labels.external_data_set | String | External data set identifier. | 
| Illumio.Workloads.labels.external_data_reference | String | External data reference identifier. | 
| Illumio.Workloads.labels.created_at | Date | Timestamp when this label was first created. | 
| Illumio.Workloads.labels.updated_at | Date | Timestamp when this label was last updated. | 
| Illumio.Workloads.labels.created_by.href | String | User who has originally created this label. | 
| Illumio.Workloads.labels.updated_by.href | String | User who has last updated this label. | 
| Illumio.Workloads.services.uptime_seconds | Number | How long since the last reboot of this box - used as a timestamp for this. | 
| Illumio.Workloads.services.created_at | Date | Timestamp when this service was first created. | 
| Illumio.Workloads.services.open_service_ports.protocol | Number | Transport protocol. | 
| Illumio.Workloads.services.open_service_ports.address | String | The local address this service is bound to. | 
| Illumio.Workloads.services.open_service_ports.port | Number | The local port this service is bound to. | 
| Illumio.Workloads.services.open_service_ports.process_name | String | The process name \(including the full path\). | 
| Illumio.Workloads.services.open_service_ports.user | String | The user account that the process is running under. | 
| Illumio.Workloads.services.open_service_ports.package | String | The RPM/DEB package that the program is part of. | 
| Illumio.Workloads.services.open_service_ports.win_service_name | String | Name of the windows service. | 
| Illumio.Workloads.vulnerabilities_summary.num_vulnerabilities | Number | Number of vulnerabilities associated with the workload. | 
| Illumio.Workloads.vulnerabilities_summary.vulnerable_port_exposure | Number | The aggregated vulnerability port exposure score of the workload across all the vulnerable ports. | 
| Illumio.Workloads.vulnerabilities_summary.vulnerable_port_wide_exposure.any | Boolean | The boolean value represents if at least one port is exposed to the internet \(any rule\) on the workload. | 
| Illumio.Workloads.vulnerabilities_summary.vulnerable_port_wide_exposure.ip_list | Boolean | The boolean value represents if at least one port is exposed to ip_list\(s\) on the workload. | 
| Illumio.Workloads.vulnerabilities_summary.vulnerability_exposure_score | Number | The aggregated vulnerability exposure score of the workload across all the vulnerable ports. | 
| Illumio.Workloads.vulnerabilities_summary.vulnerability_score | Number | The aggregated vulnerability score of the workload across all the vulnerable ports. | 
| Illumio.Workloads.vulnerabilities_summary.max_vulnerability_score | Number | The maximum of all the vulnerability scores associated with the detected_vulnerabilities on the workload. | 
| Illumio.Workloads.detected_vulnerabilities.ip_address | String | The IP address of the host where the vulnerability is found. | 
| Illumio.Workloads.detected_vulnerabilities.port | Number | The port which is associated with the vulnerability. | 
| Illumio.Workloads.detected_vulnerabilities.proto | Number | The protocol which is associated with the vulnerability. | 
| Illumio.Workloads.detected_vulnerabilities.port_exposure | Number | The exposure of the port based on the current policy. | 
| Illumio.Workloads.detected_vulnerabilities.port_wide_exposure.any | Boolean | The boolean value represents if the port is exposed to the internet \(any rule\). | 
| Illumio.Workloads.detected_vulnerabilities.port_wide_exposure.ip_list | Boolean | The boolean value represents if the port is exposed to ip_list\(s\). | 
| Illumio.Workloads.detected_vulnerabilities.workload.href | String | The URI of the workload to which this vulnerability belongs to. | 
| Illumio.Workloads.detected_vulnerabilities.vulnerability.href | String | The URI of the vulnerability class to which this vulnerability belongs to. | 
| Illumio.Workloads.detected_vulnerabilities.vulnerability.score | Number | The normalized score of the vulnerability within the range of 0 to 100. | 
| Illumio.Workloads.detected_vulnerabilities.vulnerability.name | String | The title/name of the vulnerability. | 
| Illumio.Workloads.detected_vulnerabilities.vulnerability_report.href | String | The URI of the report to which this vulnerability belongs to. | 
| Illumio.Workloads.agent.config.mode | String | DEPRECATED AND REPLACED \(Use workload enforcement_mode instead\) | 
| Illumio.Workloads.agent.config.log_traffic | Boolean | True if we want to log traffic events from this workload. | 
| Illumio.Workloads.agent.config.security_policy_update_mode | String | Defines the current policy update mode, which can be either adaptive or static based on static policy scopes. | 
| Illumio.Workloads.agent.href | String | HREF of the service agent. | 
| Illumio.Workloads.agent.secure_connect.matching_issuer_name | String | Issuer name match criteria for certificate used during establishing secure connections. | 
| Illumio.Workloads.agent.status.uid | String | The unique ID reported by the server. | 
| Illumio.Workloads.agent.status.last_heartbeat_on | Date | The last time \(rfc3339 timestamp\) a heartbeat was received from this workload. | 
| Illumio.Workloads.agent.status.uptime_seconds | Number | How long since the last reboot of this server. Recorded in DB at the time of the last heartbeat. | 
| Illumio.Workloads.agent.status.agent_version | String | Agent software version string. | 
| Illumio.Workloads.agent.status.managed_since | Date | The time \(rfc3339 timestamp\) at which this workload became managed by a VEN. | 
| Illumio.Workloads.agent.status.fw_config_current | Boolean | If this workload's firewall config is up to string'. | 
| Illumio.Workloads.agent.status.firewall_rule_count | Number | DEPRECATED WITH NO REPLACEMENT: Number of firewall rules currently installed. | 
| Illumio.Workloads.agent.status.security_policy_refresh_at | Date | DEPRECATED AND REPLACED \(USE security_policy_applied_at and security_policy_received_at INSTEAD\). | 
| Illumio.Workloads.agent.status.security_policy_applied_at | Date | Last reported time when policy was applied \(UTC\). | 
| Illumio.Workloads.agent.status.security_policy_received_at | Date | Last reported time when policy was received \(UTC\). | 
| Illumio.Workloads.agent.status.agent_health_errors.errors | Unknown | Errors associated with the security policy. | 
| Illumio.Workloads.agent.status.agent_health_errors.warnings | Unknown | Warnings associated with the security policy. | 
| Illumio.Workloads.agent.status.agent_health.type | String | This field describes the error or the warning type. | 
| Illumio.Workloads.agent.status.agent_health.severity | String | Severity of the error type. | 
| Illumio.Workloads.agent.status.agent_health.audit_event | String | The URI of the audit event that was generated for the corresponding error or warning. | 
| Illumio.Workloads.agent.status.security_policy_sync_state | String | Current state of security policy. | 
| Illumio.Workloads.agent.active_pce_fqdn | String | The FQDN of the PCE that received the agent's last heartbeat. | 
| Illumio.Workloads.agent.target_pce_fqdn | String | The FQDN of the PCE the agent will use for future connections. | 
| Illumio.Workloads.agent.type | String | Agent type. | 
| Illumio.Workloads.ven.href | String | The URI of the VEN that manages this workload. This replaces the 'agent' field of this object. | 
| Illumio.Workloads.ven.hostname | String | The hostname of the host managed by the VEN, only displayed in expanded representations. | 
| Illumio.Workloads.ven.name | String | The friendly name of the VEN, only displayed in expanded representations. | 
| Illumio.Workloads.ven.status | String | Status of the VEN, only displayed in expanded representations. | 
| Illumio.Workloads.enforcement_mode | String | Workload's enforcement mode. | 
| Illumio.Workloads.selectively_enforced_services.href | String | Workload's selective enforcement mode. | 
| Illumio.Workloads.created_at | Date | The time \(rfc3339 timestamp\) at which this workload was created. | 
| Illumio.Workloads.updated_at | Date | The time \(rfc3339 timestamp\) at which this workload was last updated. | 
| Illumio.Workloads.deleted_at | Date | The time \(rfc3339 timestamp\) at which this workload was deleted. | 
| Illumio.Workloads.created_by.href | String | The URI of the user who has created this workload. | 
| Illumio.Workloads.updated_by.href | String | The URI of the user who has last updated this workload. | 
| Illumio.Workloads.deleted_by.href | String | The URI of the user who has deleted this workload. | 
| Illumio.Workloads.container_cluster.href | String | Container cluster URI. | 
| Illumio.Workloads.container_cluster.name | String | Container cluster name. | 
| Illumio.Workloads.ike_authentication_certificate | String | IKE authentication certificate for certificate-based Secure Connect and Machine Auth connections. | 

#### Command example
```!illumio-workloads-list max_results=2```
#### Context Example
```json
{
    "Illumio": {
        "Workloads": [
            {
                "agent": {
                    "config": {
                        "log_traffic": false,
                        "mode": "selective",
                        "security_policy_update_mode": "adaptive",
                        "visibility_level": "flow_summary"
                    },
                    "href": "/orgs/1/agents/54374",
                    "secure_connect": {
                        "matching_issuer_name": ""
                    },
                    "status": {
                        "agent_version": "20.2.0",
                        "firewall_rule_count": 0,
                        "fw_config_current": false,
                        "last_heartbeat_on": "2020-10-22T01:12:06.105853Z",
                        "managed_since": "2020-10-22T01:12:05.167194Z",
                        "security_policy_sync_state": "syncing",
                        "status": "active",
                        "uptime_seconds": 0
                    },
                    "type": "Host",
                    "unpair_allowed": true
                },
                "blocked_connection_action": "drop",
                "caps": [
                    "write"
                ],
                "containers_inherit_host_policy": false,
                "created_at": "2020-10-22T01:12:05.143037Z",
                "created_by": {
                    "href": "/orgs/1/agents/54374"
                },
                "deleted": false,
                "enforcement_mode": "selective",
                "hostname": "perf-workload-54374",
                "href": "/orgs/1/workloads/77814266-7bfc-40f0-8083-14b0e9b0963a",
                "interfaces": [
                    {
                        "address": "fd00::200:a:0:d466",
                        "cidr_block": 64,
                        "loopback": false,
                        "name": "eth0",
                        "network": {
                            "href": "/orgs/1/networks/04ac9819-d438-42b6-b892-2968e32ca255"
                        },
                        "network_detection_mode": "single_private_brn"
                    },
                    {
                        "address": "10.0.212.102",
                        "cidr_block": 8,
                        "default_gateway_address": "10.0.0.1",
                        "loopback": false,
                        "name": "eth0",
                        "network": {
                            "href": "/orgs/1/networks/6736f2b5-b8a4-4db0-8df2-42508f815c1f"
                        },
                        "network_detection_mode": "single_private_brn"
                    }
                ],
                "online": false,
                "os_detail": "4.4.0-97-generic #120-Ubuntu SMP Tue Sep 19 17:28:18 UTC 2017 (Ubuntu 16.04.1 LTS)",
                "os_id": "ubuntu-x86_64-xenial",
                "public_ip": "66.151.147.220",
                "updated_at": "2022-09-19T07:46:26.932369Z",
                "updated_by": {
                    "href": "/users/65"
                },
                "ven": {
                    "href": "/orgs/1/vens/77814266-7bfc-40f0-8083-14b0e9b0963a"
                },
                "visibility_level": "flow_summary"
            },
            {
                "agent": {
                    "config": {
                        "log_traffic": false,
                        "mode": "selective",
                        "security_policy_update_mode": "adaptive",
                        "visibility_level": "flow_summary"
                    },
                    "href": "/orgs/1/agents/54388",
                    "secure_connect": {
                        "matching_issuer_name": ""
                    },
                    "status": {
                        "agent_version": "20.2.0",
                        "firewall_rule_count": 0,
                        "fw_config_current": false,
                        "last_heartbeat_on": "2020-10-22T01:12:09.76009Z",
                        "managed_since": "2020-10-22T01:12:08.569811Z",
                        "security_policy_sync_state": "syncing",
                        "status": "active",
                        "uptime_seconds": 0
                    },
                    "type": "Host",
                    "unpair_allowed": true
                },
                "blocked_connection_action": "drop",
                "caps": [
                    "write"
                ],
                "containers_inherit_host_policy": false,
                "created_at": "2020-10-22T01:12:08.528547Z",
                "created_by": {
                    "href": "/orgs/1/agents/54388"
                },
                "deleted": false,
                "enforcement_mode": "selective",
                "hostname": "perf-workload-54388",
                "href": "/orgs/1/workloads/25dc3e8c-109e-4d55-87b0-cb9795ded298",
                "interfaces": [
                    {
                        "address": "fd00::200:a:0:d474",
                        "cidr_block": 64,
                        "loopback": false,
                        "name": "eth0",
                        "network": {
                            "href": "/orgs/1/networks/04ac9819-d438-42b6-b892-2968e32ca255"
                        },
                        "network_detection_mode": "single_private_brn"
                    },
                    {
                        "address": "10.0.212.116",
                        "cidr_block": 8,
                        "default_gateway_address": "10.0.0.1",
                        "loopback": false,
                        "name": "eth0",
                        "network": {
                            "href": "/orgs/1/networks/6736f2b5-b8a4-4db0-8df2-42508f815c1f"
                        },
                        "network_detection_mode": "single_private_brn"
                    }
                ],
                "online": false,
                "os_detail": "4.4.0-97-generic #120-Ubuntu SMP Tue Sep 19 17:28:18 UTC 2017 (Ubuntu 16.04.1 LTS)",
                "os_id": "ubuntu-x86_64-xenial",
                "public_ip": "66.151.147.220",
                "updated_at": "2022-09-19T07:46:27.131486Z",
                "updated_by": {
                    "href": "/users/65"
                },
                "ven": {
                    "href": "/orgs/1/vens/25dc3e8c-109e-4d55-87b0-cb9795ded298"
                },
                "visibility_level": "flow_summary"
            }
        ]
    }
}
```

#### Human Readable Output

>### Workloads:
>
>|Workload HREF|Hostname|Enforcement Mode|Visibility Level|IP Address|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| /orgs/1/workloads/77814266-7bfc-40f0-8083-14b0e9b0963a | perf-workload-54374 | selective | flow_summary | 66.151.147.220 | 22 Oct 2020, 01:12 AM | 19 Sep 2022, 07:46 AM |
>| /orgs/1/workloads/25dc3e8c-109e-4d55-87b0-cb9795ded298 | perf-workload-54388 | selective | flow_summary | 66.151.147.220 | 22 Oct 2020, 01:12 AM | 19 Sep 2022, 07:46 AM |


### illumio-virtual-service-create
***
Creates a virtual service for a particular port & protocol, which can be further binded to workloads. Until provisioned with the 'illumio-object-provision' command, this object will remain in a draft state.


#### Base Command

`illumio-virtual-service-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Virtual service name. | Required | 
| port | Port number. | Required | 
| protocol | Communication protocol. Possible values are: TCP, UDP. Default is TCP. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.VirtualService.href | String | Label URI. | 
| Illumio.VirtualService.created_at | Date | Virtual service creation time. | 
| Illumio.VirtualService.updated_at | Date | Virtual service updated time. | 
| Illumio.VirtualService.deleted_at | Date | Virtual service deleted time. | 
| Illumio.VirtualService.created_by.href | String | URI of the user who has created the virtual service. | 
| Illumio.VirtualService.updated_by.href | String | URI of the user who has updated the virtual service. | 
| Illumio.VirtualService.deleted_by.href | String | URI of the user who has deleted the virtual service. | 
| Illumio.VirtualService.update_type | String | What type of modification has been done on the virtual service. | 
| Illumio.VirtualService.name | String | Name of the virtual service. | 
| Illumio.VirtualService.description | String | Description of the virtual service. | 
| Illumio.VirtualService.pce_fqdn | String | PCE FQDN to assign to the virtual service. | 
| Illumio.VirtualService.service_ports.port | Number | Port of the virtual service. | 
| Illumio.VirtualService.service_ports.proto | Number | Proto of the virtual service. | 
| Illumio.VirtualService.labels | Unknown | Labels of the virtual service. | 
| Illumio.VirtualService.ip_overrides | Unknown | Array of IPs or CIDRs as IP overrides. | 
| Illumio.VirtualService.apply_to | String | Firewall rule target for workloads bound to this virtual service: host_only or internal_bridge_network. | 
| Illumio.VirtualService.caps | Unknown | Array of permissions for the entity for the current user - an empty array implies read only access. | 
| Illumio.VirtualService.service_addresses | Unknown | Service addresses of the virtual service. | 

#### Command example
```!illumio-virtual-service-create name=trail-service-test-103 port=8443 protocol=TCP```
#### Context Example
```json
{
    "Illumio": {
        "VirtualService": {
            "apply_to": "host_only",
            "caps": [
                "write",
                "provision",
                "delete"
            ],
            "created_at": "2022-09-19T09:12:53.320Z",
            "created_by": {
                "href": "/users/68"
            },
            "href": "/orgs/1/sec_policy/draft/virtual_services/308cc90b-00c3-4578-aca5-352ed50b770e",
            "name": "trail-service-test-103",
            "service_ports": [
                {
                    "port": 8443,
                    "proto": 6
                }
            ],
            "update_type": "create",
            "updated_at": "2022-09-19T09:12:53.324Z",
            "updated_by": {
                "href": "/users/68"
            }
        }
    }
}
```

#### Human Readable Output

>### Virtual Service:
>#### Successfully created virtual service: /orgs/1/sec_policy/draft/virtual_services/308cc90b-00c3-4578-aca5-352ed50b770e
>
>|Virtual Service HREF|Created At|Updated At|Name|Service Port|Service Protocol|
>|---|---|---|---|---|---|
>| /orgs/1/sec_policy/draft/virtual_services/308cc90b-00c3-4578-aca5-352ed50b770e | 19 Sep 2022, 09:12 AM | 19 Sep 2022, 09:12 AM | trail-service-test-103 | 8443 | TCP |


### illumio-traffic-analysis
***
Retrieves traffic flow of a particular port & protocol within the specified time range based on policy decisions.


#### Base Command

`illumio-traffic-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port | Port number. | Required | 
| protocol | Communication protocol.<br/><br/>Supported values are: 'tcp' and 'udp'. Possible values are: tcp, udp. Default is tcp. | Optional | 
| start_time | Start of analysis range.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. Default is 1 week ago. | Optional | 
| end_time | End of analysis range.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z. Default is now. | Optional | 
| policy_decisions | List of policy decisions to include in the search results. Supports comma-separated values.<br/><br/>Supported values are: 'potentially_blocked', 'blocked', 'unknown', and 'allowed'. Default is potentially_blocked, unknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.TrafficFlows.src.ip | String | IP of the source. | 
| Illumio.TrafficFlows.dst.ip | String | Destination IP address. | 
| Illumio.TrafficFlows.dst.workload.hostname | String | Destination workload hostname. | 
| Illumio.TrafficFlows.dst.workload.name | String | Destination workload name. | 
| Illumio.TrafficFlows.dst.workload.href | String | Destination workload URI. | 
| Illumio.TrafficFlows.dst.workload.os_type | String | Destination workload OS type. | 
| Illumio.TrafficFlows.dst.workload.labels.href | String | Destination label URI. | 
| Illumio.TrafficFlows.dst.workload.labels.key | String | Destination workload label key. | 
| Illumio.TrafficFlows.dst.workload.labels.value | String | Destination workload label value. | 
| Illumio.TrafficFlows.service.port | Number | Port of the traffic. | 
| Illumio.TrafficFlows.service.proto | Number | Protocol number of the traffic. | 
| Illumio.TrafficFlows.num_connections | Number | Number of traffic flows reported in connections. | 
| Illumio.TrafficFlows.policy_decisions | String | Indicates the policy decision for the flow. Indicates if the traffic flow is allowed, potentially blocked \(but allowed\), or blocked. | 
| Illumio.TrafficFlows.state | String | State of the flow. | 
| Illumio.TrafficFlows.flow_direction | String | Flow direction of the traffic. | 
| Illumio.TrafficFlows.dst_bi | Number | Bytes received till now by the destination over the flow during the interval. | 
| Illumio.TrafficFlows.dst_bo | Number | Bytes sent till now by the destination over the flow during the interval. | 
| Illumio.TrafficFlows.timestamp_range.last_detected | Date | Time range when traffic was last detected. | 
| Illumio.TrafficFlows.timestamp_range.first_detected | Date | Time range when traffic was first detected. | 

#### Command example
```!illumio-traffic-analysis port=8443```
#### Context Example
```json
{
    "Illumio": {
        "TrafficFlows": [
            {
                "dst": {
                    "ip": "10.8.4.233",
                    "workload": {
                        "hostname": "demo-snow-workload-2",
                        "href": "/orgs/1/workloads/a1a2bd2f-b74b-4068-a177-11b0cb1c92c4",
                        "labels": [
                            {
                                "href": "/orgs/1/labels/3089"
                            },
                            {
                                "href": "/orgs/1/labels/10"
                            },
                            {
                                "href": "/orgs/1/labels/27148"
                            },
                            {
                                "href": "/orgs/1/labels/27153"
                            }
                        ],
                        "name": "demo-snow-workload-2",
                        "os_type": "linux"
                    }
                },
                "dst_bi": 0,
                "dst_bo": 0,
                "flow_direction": "inbound",
                "num_connections": 1,
                "policy_decision": "potentially_blocked",
                "service": {
                    "port": 8443,
                    "proto": 6
                },
                "src": {
                    "ip": "10.2.8.183"
                },
                "state": "closed",
                "timestamp_range": {
                    "first_detected": "2022-09-17T07:53:29Z",
                    "last_detected": "2022-09-17T07:53:29Z"
                }
            },
            {
                "dst": {
                    "ip": "52.10.17.167"
                },
                "dst_bi": 6,
                "dst_bo": 6,
                "flow_direction": "outbound",
                "num_connections": 6,
                "policy_decision": "unknown",
                "service": {
                    "port": 8443,
                    "proto": 6,
                    "user_name": "root"
                },
                "src": {
                    "ip": "10.50.2.50",
                    "workload": {
                        "hostname": "localhost.localdomain",
                        "href": "/orgs/1/workloads/4ef7da86-a432-4201-a6e1-eb802b23b657",
                        "name": "localhost.localdomain",
                        "os_type": "linux"
                    }
                },
                "state": "snapshot",
                "timestamp_range": {
                    "first_detected": "2022-09-14T13:25:44Z",
                    "last_detected": "2022-09-14T13:25:44Z"
                }
            },
            {
                "dst": {
                    "ip": "10.8.4.216",
                    "workload": {
                        "hostname": "demo-snow-workload-1",
                        "href": "/orgs/1/workloads/1f28c4e8-64ec-48b9-aa25-27611b7210f6",
                        "labels": [
                            {
                                "href": "/orgs/1/labels/27357"
                            }
                        ],
                        "name": "demo-snow-workload-1",
                        "os_type": "linux"
                    }
                },
                "dst_bi": 0,
                "dst_bo": 0,
                "flow_direction": "inbound",
                "num_connections": 1,
                "policy_decision": "potentially_blocked",
                "service": {
                    "port": 8443,
                    "proto": 6
                },
                "src": {
                    "ip": "10.2.8.183"
                },
                "state": "closed",
                "timestamp_range": {
                    "first_detected": "2022-09-17T07:53:29Z",
                    "last_detected": "2022-09-17T07:53:29Z"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Traffic Analysis:
>|Source IP|Destination IP| Destination Workload Hostname |Service Port|Service Protocol|Policy Decision|State|Flow Direction|First Detected|Last Detected|
>|---|---|---|---|---|---|---|---|---|---|
>| 10.2.8.183 | 10.8.4.233 | demo-snow-workload-2 | 8443 | TCP | potentially_blocked | closed | inbound | 17 Sep 2022, 07:53 AM | 17 Sep 2022, 07:53 AM |
>| 10.50.2.50 | 52.10.17.167 |   | 8443 | TCP | unknown | snapshot | outbound | 14 Sep 2022, 01:25 PM | 14 Sep 2022, 01:25 PM |
>| 10.2.8.183 | 10.8.4.216 | demo-snow-workload-1 | 8443 | TCP | potentially_blocked | closed | inbound | 17 Sep 2022, 07:53 AM | 17 Sep 2022, 07:53 AM |


### illumio-service-binding-create
***
Binds the existing or a new virtual service to the workloads.


#### Base Command

`illumio-service-binding-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workloads | Workload HREFs to bind. Supports comma-separated values.<br/><br/>Note: Users can retrieve the list of Href's by executing the "illumio-workloads-list" or the "illumio-traffic-analysis" command. | Required | 
| virtual_service | Virtual service HREF to bind the workloads to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.ServiceBinding.status | String | Indicates the status of a request. | 
| Illumio.ServiceBinding.href | String | Label URI. | 

#### Command example
```!illumio-service-binding-create workloads=/orgs/1/workloads/a7ae549d-33b1-450c-aace-8454e82b88cf virtual_service=/orgs/1/sec_policy/draft/virtual_services/79cc1d7d-7460-43fc-a3ac-45cf73022bd7```
#### Context Example
```json
{
    "Illumio": {
        "ServiceBinding": {
            "service_bindings": [
                {
                    "href": "/orgs/1/service_bindings/27209478-ca91-4f4a-bb1e-774e4c403794"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Service Binding:
>#### Workloads have been bounded to the virtual service successfully.
>|Service Binding HREF|Status|
>|---|---|
>| /orgs/1/service_bindings/27209478-ca91-4f4a-bb1e-774e4c403794 | created |


### illumio-workload-get
***
Retrieves the details of the workload based on the provided workload's HREF.


#### Base Command

`illumio-workload-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| href | Workload HREF.<br/>Note: Users can retrieve the list of Href's by executing the "illumio-workloads-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.Workload.href | String | URI of workload. | 
| Illumio.Workload.deleted | Boolean | Whether this workload has been deleted or not. | 
| Illumio.Workload.delete_type | String | Workload deletion type. | 
| Illumio.Workload.name | String | Interface name. | 
| Illumio.Workload.description | String | The description of this workload. | 
| Illumio.Workload.managed | Boolean | True if the workload is managed, else false. | 
| Illumio.Workload.hostname | String | The hostname of this workload. | 
| Illumio.Workload.service_principal_name | String | The Kerberos Service Principal Name \(SPN\). | 
| Illumio.Workload.agent_to_pce_certificate_authentication_id | String | PKI Certificate identifier to be used by the PCE for authenticating the VEN. | 
| Illumio.Workload.distinguished_name | String | X.509 Subject distinguished name. | 
| Illumio.Workload.public_ip | String | The public IP address of the server. | 
| Illumio.Workload.external_data_set | String | External data set identifier. | 
| Illumio.Workload.external_data_reference | String | External data reference identifier. | 
| Illumio.Workload.interfaces.name | String | Interface name. | 
| Illumio.Workload.interfaces.link_state | String | Link state. | 
| Illumio.Workload.interfaces.address | String | The IP address to assign to this interface. | 
| Illumio.Workload.interfaces.cidr_block | Number | The number of bits in the subnet /24 is 255.255.255.0. | 
| Illumio.Workload.interfaces.default_gateway_address | String | The IP address of the default gateway. | 
| Illumio.Workload.interfaces.network.href | String | URI of the network. | 
| Illumio.Workload.interfaces.network_detection_mode | String | Network detection mode. | 
| Illumio.Workload.interfaces.friendly_name | String | User-friendly name for interface. | 
| Illumio.Workload.service_provider | String | Service provider. | 
| Illumio.Workload.data_center | String | Data center. | 
| Illumio.Workload.data_center_zone | String | Data center zone. | 
| Illumio.Workload.os_id | String | Our OS identifier. | 
| Illumio.Workload.os_detail | String | Additional OS details - just displayed to the end user. | 
| Illumio.Workload.online | Boolean | If this workload is online. | 
| Illumio.Workload.firewall_coexistence.illumio_primary | Boolean | Illumio is the primary firewall if set to true. | 
| Illumio.Workload.containers_inherit_host_policy | Boolean | This workload will apply the policy it receives both to itself and the containers hosted by it. | 
| Illumio.Workload.blocked_connection_action | String | Firewall action for blocked connections. | 
| Illumio.Workload.labels.href | String | URI of this label. | 
| Illumio.Workload.labels.deleted | Boolean | Assigned labels. | 
| Illumio.Workload.labels.key | String | Key in key-value pair. | 
| Illumio.Workload.labels.value | String | Value in key-value pair. | 
| Illumio.Workload.labels.external_data_set | String | External data set identifier. | 
| Illumio.Workload.labels.external_data_reference | String | External data reference identifier. | 
| Illumio.Workload.labels.created_at | Date | Timestamp when this label was first created. | 
| Illumio.Workload.labels.updated_at | Date | Timestamp when this label was last updated. | 
| Illumio.Workload.labels.created_by.href | String | User who has originally created this label. | 
| Illumio.Workload.labels.updated_by.href | String | User who has last updated this label. | 
| Illumio.Workload.services.uptime_seconds | Number | How long since the last reboot of this box - used as a timestamp for this. | 
| Illumio.Workload.services.created_at | Date | Timestamp when this service was first created. | 
| Illumio.Workload.services.open_service_ports.protocol | Number | Transport protocol. | 
| Illumio.Workload.services.open_service_ports.address | String | The local address this service is bound to. | 
| Illumio.Workload.services.open_service_ports.port | Number | The local port this service is bound to. | 
| Illumio.Workload.services.open_service_ports.process_name | String | The process name \(including the full path\). | 
| Illumio.Workload.services.open_service_ports.user | String | The user account that the process is running under. | 
| Illumio.Workload.services.open_service_ports.package | String | The RPM/DEB package that the program is part of. | 
| Illumio.Workload.services.open_service_ports.win_service_name | String | Name of the windows service. | 
| Illumio.Workload.vulnerabilities_summary.num_vulnerabilities | Number | Number of vulnerabilities associated with the workload. | 
| Illumio.Workload.vulnerabilities_summary.vulnerable_port_exposure | Number | The aggregated vulnerability port exposure score of the workload across all the vulnerable ports. | 
| Illumio.Workload.vulnerabilities_summary.vulnerable_port_wide_exposure.any | Boolean | The boolean value represents if at least one port is exposed to the internet \(any rule\) on the workload. | 
| Illumio.Workload.vulnerabilities_summary.vulnerable_port_wide_exposure.ip_list | Boolean | The boolean value represents if at least one port is exposed to ip_list\(s\) on the workload. | 
| Illumio.Workload.vulnerabilities_summary.vulnerability_exposure_score | Number | The aggregated vulnerability exposure score of the workload across all the vulnerable ports. | 
| Illumio.Workload.vulnerabilities_summary.vulnerability_score | Number | The aggregated vulnerability score of the workload across all the vulnerable ports. | 
| Illumio.Workload.vulnerabilities_summary.max_vulnerability_score | Number | The maximum of all the vulnerability scores associated with the detected_vulnerabilities on the workload. | 
| Illumio.Workload.detected_vulnerabilities.ip_address | String | The IP address of the host where the vulnerability is found. | 
| Illumio.Workload.detected_vulnerabilities.port | Number | The port which is associated with the vulnerability. | 
| Illumio.Workload.detected_vulnerabilities.proto | Number | The protocol which is associated with the vulnerability. | 
| Illumio.Workload.detected_vulnerabilities.port_exposure | Number | The exposure of the port based on the current policy. | 
| Illumio.Workload.detected_vulnerabilities.port_wide_exposure.any | Boolean | The boolean value represents if the port is exposed to the internet \(any rule\). | 
| Illumio.Workload.detected_vulnerabilities.port_wide_exposure.ip_list | Boolean | The boolean value represents if the port is exposed to ip_list\(s\). | 
| Illumio.Workload.detected_vulnerabilities.workload.href | String | The URI of the workload to which this vulnerability belongs to. | 
| Illumio.Workload.detected_vulnerabilities.vulnerability.href | String | The URI of the vulnerability class to which this vulnerability belongs to. | 
| Illumio.Workload.detected_vulnerabilities.vulnerability.score | Number | The normalized score of the vulnerability within the range of 0 to 100. | 
| Illumio.Workload.detected_vulnerabilities.vulnerability.name | String | The title/name of the vulnerability. | 
| Illumio.Workload.detected_vulnerabilities.vulnerability_report.href | String | The URI of the report to which this vulnerability belongs to. | 
| Illumio.Workload.agent.config.mode | String | DEPRECATED AND REPLACED \(Use workload enforcement_mode instead\) | 
| Illumio.Workload.agent.config.log_traffic | Boolean | True if we want to log traffic events from this workload. | 
| Illumio.Workload.agent.config.security_policy_update_mode | String | Defines the current policy update mode, which can be either adaptive or static based on static policy scopes. | 
| Illumio.Workload.agent.href | String | HREF of the service agent. | 
| Illumio.Workload.agent.secure_connect.matching_issuer_name | String | Issuer name match criteria for certificate used during establishing secure connections. | 
| Illumio.Workload.agent.status.uid | String | The unique ID reported by the server. | 
| Illumio.Workload.agent.status.last_heartbeat_on | Date | The last time \(rfc3339 timestamp\) a heartbeat was received from this workload. | 
| Illumio.Workload.agent.status.uptime_seconds | Number | How long since the last reboot of this server. Recorded in DB at the time of the last heartbeat. | 
| Illumio.Workload.agent.status.agent_version | String | Agent software version string. | 
| Illumio.Workload.agent.status.managed_since | Date | The time \(rfc3339 timestamp\) at which this workload became managed by a VEN. | 
| Illumio.Workload.agent.status.fw_config_current | Boolean | If this workload's firewall config is up to string'. | 
| Illumio.Workload.agent.status.firewall_rule_count | Number | DEPRECATED WITH NO REPLACEMENT: Number of firewall rules currently installed. | 
| Illumio.Workload.agent.status.security_policy_refresh_at | Date | DEPRECATED AND REPLACED \(USE security_policy_applied_at and security_policy_received_at INSTEAD\). | 
| Illumio.Workload.agent.status.security_policy_applied_at | Date | Last reported time when policy was applied \(UTC\). | 
| Illumio.Workload.agent.status.security_policy_received_at | Date | Last reported time when policy was received \(UTC\). | 
| Illumio.Workload.agent.status.agent_health_errors.errors | Unknown | Errors associated with the security policy. | 
| Illumio.Workload.agent.status.agent_health_errors.warnings | Unknown | Warnings associated with the security policy. | 
| Illumio.Workload.agent.status.agent_health.type | String | This field describes the error or the warning type. | 
| Illumio.Workload.agent.status.agent_health.severity | String | Severity of the error type. | 
| Illumio.Workload.agent.status.agent_health.audit_event | String | The URI of the audit event that was generated for the corresponding error or warning. | 
| Illumio.Workload.agent.status.security_policy_sync_state | String | Current state of security policy. | 
| Illumio.Workload.agent.active_pce_fqdn | String | The FQDN of the PCE that received the agent's last heartbeat. | 
| Illumio.Workload.agent.target_pce_fqdn | String | The FQDN of the PCE the agent will use for future connections. | 
| Illumio.Workload.agent.type | String | Agent type. | 
| Illumio.Workload.ven.href | String | The URI of the VEN that manages this workload. This replaces the 'agent' field of this object. | 
| Illumio.Workload.ven.hostname | String | The hostname of the host managed by the VEN, only displayed in expanded representations. | 
| Illumio.Workload.ven.name | String | The friendly name of the VEN, only displayed in expanded representations. | 
| Illumio.Workload.ven.status | String | Status of the VEN, only displayed in expanded representations. | 
| Illumio.Workload.enforcement_mode | String | Workload's enforcement mode. | 
| Illumio.Workload.selectively_enforced_services.href | String | Workload's selective enforcement mode. | 
| Illumio.Workload.created_at | Date | The time \(rfc3339 timestamp\) at which this workload was created. | 
| Illumio.Workload.updated_at | Date | The time \(rfc3339 timestamp\) at which this workload was last updated. | 
| Illumio.Workload.deleted_at | Date | The time \(rfc3339 timestamp\) at which this workload was deleted. | 
| Illumio.Workload.created_by.href | String | The URI of the user who has created this workload. | 
| Illumio.Workload.updated_by.href | String | The URI of the user who has last updated this workload. | 
| Illumio.Workload.deleted_by.href | String | The URI of the user who has deleted this workload. | 
| Illumio.Workload.container_cluster.href | String | Container cluster URI. | 
| Illumio.Workload.container_cluster.name | String | Container cluster name. | 
| Illumio.Workload.ike_authentication_certificate | String | IKE authentication certificate for certificate-based Secure Connect and Machine Auth connections. | 

#### Command example
```!illumio-workload-get href=/orgs/1/workloads/b0426bc0-c6c6-4ef8-bd8a-2a1771f97503```
#### Context Example
```json
{
    "Illumio": {
        "Workload": {
            "agent": {
                "config": {
                    "log_traffic": false,
                    "mode": "selective",
                    "security_policy_update_mode": "adaptive",
                    "visibility_level": "flow_summary"
                },
                "href": "/orgs/1/agents/56770",
                "secure_connect": {
                    "matching_issuer_name": ""
                },
                "status": {
                    "agent_version": "20.2.0",
                    "firewall_rule_count": 0,
                    "fw_config_current": false,
                    "last_heartbeat_on": "2020-10-22T01:27:43.213Z",
                    "managed_since": "2020-10-22T01:27:42.228Z",
                    "security_policy_sync_state": "syncing",
                    "status": "active",
                    "uptime_seconds": 0
                },
                "type": "Host",
                "unpair_allowed": true
            },
            "blocked_connection_action": "drop",
            "caps": [
                "write"
            ],
            "containers_inherit_host_policy": false,
            "created_at": "2020-10-22T01:27:42.201Z",
            "created_by": {
                "href": "/orgs/1/agents/56770"
            },
            "deleted": false,
            "enforcement_mode": "selective",
            "hostname": "perf-workload-56770",
            "href": "/orgs/1/workloads/b0426bc0-c6c6-4ef8-bd8a-2a1771f97503",
            "interfaces": [
                {
                    "address": "fd00::200:a:0:ddc2",
                    "cidr_block": 64,
                    "loopback": false,
                    "name": "eth0",
                    "network": {
                        "href": "/orgs/1/networks/04ac9819-d438-42b6-b892-2968e32ca255"
                    },
                    "network_detection_mode": "single_private_brn"
                },
                {
                    "address": "10.0.221.194",
                    "cidr_block": 8,
                    "default_gateway_address": "10.0.0.1",
                    "loopback": false,
                    "name": "eth0",
                    "network": {
                        "href": "/orgs/1/networks/6736f2b5-b8a4-4db0-8df2-42508f815c1f"
                    },
                    "network_detection_mode": "single_private_brn"
                }
            ],
            "num_enforcement_boundaries": 4,
            "online": false,
            "os_detail": "4.4.0-97-generic #120-Ubuntu SMP Tue Sep 19 17:28:18 UTC 2017 (Ubuntu 16.04.1 LTS)",
            "os_id": "ubuntu-x86_64-xenial",
            "public_ip": "66.151.147.220",
            "selectively_enforced_services": [
                {
                    "port": 8443,
                    "proto": 6
                },
                {
                    "port": 22,
                    "proto": 6
                },
                {
                    "port": 443,
                    "proto": 6
                },
                {
                    "port": 3,
                    "proto": 17
                },
                {
                    "port": 1,
                    "proto": 6
                }
            ],
            "services": {
                "open_service_ports": [
                    {
                        "address": "0.0.0.0",
                        "port": 161,
                        "process_name": "snmpd",
                        "protocol": 6,
                        "user": "root"
                    },
                    {
                        "address": "0.0.0.0",
                        "port": 53,
                        "process_name": "bind",
                        "protocol": 6,
                        "user": "root"
                    },
                    {
                        "address": "0.0.0.0",
                        "port": 5432,
                        "process_name": "postgres",
                        "protocol": 6,
                        "user": "root"
                    },
                    {
                        "address": "0.0.0.0",
                        "port": 67,
                        "process_name": "dhcpd",
                        "protocol": 17,
                        "user": "root"
                    },
                    {
                        "address": "0.0.0.0",
                        "port": 80,
                        "process_name": "httpd",
                        "protocol": 6,
                        "user": "root"
                    }
                ],
                "uptime_seconds": 120708
            },
            "updated_at": "2022-09-19T07:47:17.806Z",
            "updated_by": {
                "href": "/users/65"
            },
            "ven": {
                "href": "/orgs/1/vens/b0426bc0-c6c6-4ef8-bd8a-2a1771f97503"
            },
            "visibility_level": "flow_summary"
        }
    }
}
```

#### Human Readable Output

>### Workload Details:
>|Workload HREF|Created At|Updated At|Hostname|
>|---|---|---|---|
>| /orgs/1/workloads/b0426bc0-c6c6-4ef8-bd8a-2a1771f97503 | 22 Oct 2020, 01:27 AM | 19 Sep 2022, 07:47 AM | perf-workload-56770 |


### illumio-enforcement-mode-update
***
Update the Enforcement Mode for one or more workloads.


#### Base Command

`illumio-enforcement-mode-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enforcement_mode | New enforcement mode to apply. Possible values are: Idle, Visibility_only, Selective, Full. | Required | 
| workloads | List of workload HREFs to update. Supports comma separated values. <br/>Note: Users can retrieve the list of Href's by executing the "illumio-workloads-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.UpdateStatuses.href | String | Enforcement mode update workload URI. | 
| Illumio.UpdateStatuses.status | String | Whether the operation was successful or not. | 

#### Command example
```!illumio-enforcement-mode-update enforcement_mode=Visibility_only workloads=/orgs/1/workloads/b98b4456-e24b-4c01-a3b8-f53cd85f1fab```
#### Context Example
```json
{
    "Illumio": {
        "UpdateStatuses": {
            "href": "/orgs/1/workloads/b98b4456-e24b-4c01-a3b8-f53cd85f1fab",
            "status": "Updated"
        }
    }
}
```

#### Human Readable Output

>### Workload Enforcement Update:
>#### Successfully updated enforcement mode for 1 workloads, 0 workloads failed to update
>|Workload HREF|Status|
>|---|---|
>| /orgs/1/workloads/b98b4456-e24b-4c01-a3b8-f53cd85f1fab | Updated |


### illumio-object-provision
***
A utility method for provisioning policy objects from draft to active state. Policy objects only affect the network once they've been provisioned.


#### Base Command

`illumio-object-provision`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_policy_objects | List of security policy object HREFs to provision. Supports comma-separated values. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.PolicyState.href | String | Object label URI. | 
| Illumio.PolicyState.commit_message | String | Message for the provisioning. | 
| Illumio.PolicyState.version | Number | Version of the object. | 
| Illumio.PolicyState.workloads_affected | Number | Number of workloads affected. | 
| Illumio.PolicyState.created_by.href | String | Created by label URI. | 
| Illumio.PolicyState.object_counts.rule_sets | Number | Count of rulesets. | 
| Illumio.PolicyState.object_counts.services | Number | Count of services. | 
| Illumio.PolicyState.object_counts.ip_lists | Number | Count of IP lists. | 
| Illumio.PolicyState.object_counts.firewall_settings | Number | Count of firewall settings. | 
| Illumio.PolicyState.object_counts.label_groups | Number | Count of label groups. | 
| Illumio.PolicyState.object_counts.secure_connect_gateways | Number | Count of secure connection gateways. | 
| Illumio.PolicyState.object_counts.virtual_servers | Number | Count of virtual servers. | 
| Illumio.PolicyState.object_counts.enforcement_boudaries | Number | Count of enforcement boundaries. | 
| Illumio.PolicyState.object_counts.virtual_services | Number | Count of virtual services. | 
| Illumio.PolicyState.provisioned_hrefs | Unknown | List of active hrefs after provisioning. | 

#### Command example
```!illumio-object-provision security_policy_objects=/orgs/1/sec_policy/draft/virtual_services/fb651a8f-c56c-41c6-b5c6-d7e3e9c1124a```
#### Context Example
```json
{
    "Illumio": {
        "PolicyState": {
            "commit_message": "XSOAR - 2022-09-19T09:14:00.911096\nProvisioning following objects:\n/orgs/1/sec_policy/draft/virtual_services/fb651a8f-c56c-41c6-b5c6-d7e3e9c1124a",
            "created_at": "2022-09-19T09:14:02.266Z",
            "created_by": {
                "href": "/users/68"
            },
            "href": "/orgs/1/sec_policy/1770",
            "object_counts": {
                "enforcement_boundaries": 4,
                "firewall_settings": 1,
                "ip_lists": 26,
                "label_groups": 17,
                "rule_sets": 5,
                "secure_connect_gateways": 0,
                "services": 17,
                "virtual_servers": 0,
                "virtual_services": 229
            },
            "provisioned_hrefs": [
                "/orgs/1/sec_policy/active/virtual_services/fb651a8f-c56c-41c6-b5c6-d7e3e9c1124a"
            ],
            "version": 1770,
            "workloads_affected": 0
        }
    }
}
```

#### Human Readable Output

>### Provision Objects:
>### Provision is completed for /orgs/1/sec_policy/1770
>|Provision Object URI|Commit Message|Created At|
>|---|---|---|
>| /orgs/1/sec_policy/1770 | XSOAR - 2022-09-19T09:14:00.911096<br/>Provisioning following objects:<br/>/orgs/1/sec_policy/draft/virtual_services/fb651a8f-c56c-41c6-b5c6-d7e3e9c1124a | 19 Sep 2022, 09:14 AM |


### illumio-ip-list-get
***
Retrieves the list of IPs based on the name of the IP list.


#### Base Command

`illumio-ip-list-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| href | URI of the IP list.<br/>Note: Users can retrieve the list of Href's of IP by executing the "illumio-ip-lists-get" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.IPList.href | String | URI of the IP list. | 
| Illumio.IPList.description | String | Description of IP list. | 
| Illumio.IPList.external_data_set | String | External data set identifier. | 
| Illumio.IPList.external_data_reference | String | External data reference identifier. | 
| Illumio.IPList.created_at | Date | Time stamp when this IP list was first created. | 
| Illumio.IPList.updated_at | Date | Time stamp when this IP List was last updated. | 
| Illumio.IPList.deleted_at | Date | Time stamp when this IP List was deleted. | 
| Illumio.IPList.created_by.href | String | User who originally created this IP List. | 
| Illumio.IPList.updated_by.href | String | User who last updated this IP List. | 
| Illumio.IPList.deleted_by.href | String | User who has deleted this IP List. | 
| Illumio.IPList.name | String | Name \(must be unique\). | 
| Illumio.IPList.ip_ranges.description | String | Description of given IP range. | 
| Illumio.IPList.ip_ranges.from_ip | String | IP address or a low end of IP range. Might be specified with CIDR notation. | 
| Illumio.IPList.ip_ranges.to_ip | String | High end of an IP range. | 
| Illumio.IPList.ip_ranges.exclusion | String | Whether this IP address is an exclusion. Exclusions must be a strict subset of inclusive IP addresses. | 
| Illumio.IPList.fqdns.fqdn | String | Fully qualified domain name. | 
| Illumio.IPList.fqdns.description | String | Description of FQDN. | 

#### Command example
```!illumio-ip-list-get href=/orgs/1/sec_policy/draft/ip_lists/35```
#### Context Example
```json
{
    "Illumio": {
        "IPList": {
            "created_at": "2021-05-14T08:17:05.569Z",
            "created_by": {
                "href": "/users/15"
            },
            "description": "PCE ip range",
            "fqdns": [
                {
                    "description": "fqdn description",
                    "fqdn": "fqdn-demo"
                }
            ],
            "href": "/orgs/1/sec_policy/draft/ip_lists/35",
            "ip_ranges": [
                {
                    "description": "PCE ip tange",
                    "exclusion": false,
                    "from_ip": "10.6.4.223",
                    "to_ip": "10.6.4.226"
                }
            ],
            "name": "PCE ip range",
            "updated_at": "2021-05-14T08:17:05.572Z",
            "updated_by": {
                "href": "/users/15"
            }
        }
    }
}
```

#### Human Readable Output

>### IP List Details:
>|IP List HREF|Name|Created At|Updated At|IP Ranges|FQDNS|
>|---|---|---|---|---|---|
>| /orgs/1/sec_policy/draft/ip_lists/35 | PCE ip range | 14 May 2021, 08:17 AM | 14 May 2021, 08:17 AM | 10.6.4.223 - 10.6.4.226 | 2x2devtestscr1.ilabs.io |


### illumio-ruleset-create
***
Creates a ruleset with a unique name. Until provisioned with the 'illumio-object-provision' command, this object will remain in a draft state.


#### Base Command

`illumio-ruleset-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Ruleset name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.Ruleset.href | String | Label URI. | 
| Illumio.Ruleset.created_at | Date | Ruleset creation time. | 
| Illumio.Ruleset.updated_at | Date | Ruleset updation time. | 
| Illumio.Ruleset.deleted_at | Date | Ruleset deletion time. | 
| Illumio.Ruleset.created_by.href | String | URI of the user who has created the ruleset. | 
| Illumio.Ruleset.updated_by.href | String | URI of the user who has updated the ruleset. | 
| Illumio.Ruleset.deleted_by.href | String | URI of the user who has deleted the ruleset. | 
| Illumio.Ruleset.update_type | String | Type of modification done on the ruleset. | 
| Illumio.Ruleset.name | String | Name of the ruleset. | 
| Illumio.Ruleset.description | String | Description of the ruleset. | 
| Illumio.Ruleset.enabled | Boolean | Whether the ruleset is enabled or not. | 
| Illumio.Ruleset.scopes | Unknown | Scope of the ruleset. | 
| Illumio.Ruleset.rules | Unknown | Rules in the ruleset. | 
| Illumio.Ruleset.ip_tables_rules | Unknown | Array of IP table rules in the ruleset. | 
| Illumio.Ruleset.caps | Unknown | Array of permissions for the entity to the current user - an empty array implies read-only access. | 

#### Command example
```!illumio-ruleset-create name=trial-ruleset-test-103```
#### Context Example
```json
{
    "Illumio": {
        "Ruleset": {
            "caps": [
                "write",
                "provision"
            ],
            "created_at": "2022-09-19T09:14:25.444Z",
            "created_by": {
                "href": "/users/68"
            },
            "enabled": true,
            "href": "/orgs/1/sec_policy/draft/rule_sets/2409",
            "name": "trial-ruleset-test-103",
            "update_type": "create",
            "updated_at": "2022-09-19T09:14:25.444Z",
            "updated_by": {
                "href": "/users/68"
            }
        }
    }
}
```

#### Human Readable Output

>### Ruleset trial-ruleset-test-103 has been created successfully.
>|Ruleset URI|Name|Created At|Updated At|Enabled|Caps|
>|---|---|---|---|---|---|
>| /orgs/1/sec_policy/draft/rule_sets/2409 | trial-ruleset-test-103 | 19 Sep 2022, 09:14 AM | 19 Sep 2022, 09:14 AM | true | write,<br/>provision |


### illumio-rule-create
***
Creates & assigns rules to a particular ruleset. Added or updated Rules will remain in draft state until their containing Rule Set is provisioned using the "illumio-object-provision" command.


#### Base Command

`illumio-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ruleset_href | HREF of the ruleset in which to create the rule. | Required | 
| providers | HREFs of entities to be used as providers for the rule. For all workloads provide "ams". Supports comma-separated values. | Required | 
| consumers | HREFs of entities to be used as consumers for the rule. For all workloads provide "ams". Supports comma-separated values. | Required | 
| resolve_providers_as | Provider objects the rule should apply to. Supports comma separated values.<br/><br/>Supported values are: 'workloads' and 'virtual_services'. Default is workloads. | Optional | 
| resolve_consumers_as | Consumer objects the rule should apply to. Supports comma separated values.<br/><br/>Supported values are: 'workloads' and 'virtual_services'. Default is workloads. | Optional | 
| ingress_services | Service URIs. Supports comma separated values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Illumio.Rule.href | String | Label URI. | 
| Illumio.Rule.created_at | Date | Rule creation time. | 
| Illumio.Rule.updated_at | Date | Rule updated time. | 
| Illumio.Rule.deleted_at | Date | Rule deleted time. | 
| Illumio.Rule.created_by.href | String | URI of the user who has created the rule. | 
| Illumio.Rule.updated_by.href | String | URI of the user who has updated the rule. | 
| Illumio.Rule.deleted_by | String | URI of the user who has deleted the rule. | 
| Illumio.Rule.update_type | String | Type of modification done on the rule. | 
| Illumio.Rule.description | String | Description of the rule. | 
| Illumio.Rule.enabled | Boolean | Whether the rule is enabled or not. | 
| Illumio.Rule.providers.label.href | String | Providers label URI. | 
| Illumio.Rule.providers.actors | String | All workloads. | 
| Illumio.Rule.providers.label_group.href | String | Providers label group URI. | 
| Illumio.Rule.providers.virtual_server.href | String | Providers virtual server URI. | 
| Illumio.Rule.providers.virtual_service.href | String | Provider virtual service URI. | 
| Illumio.Rule.providers.ip_list.href | String | Provider ip list URI. | 
| Illumio.Rule.providers.workload.href | String | Provider workload URI. | 
| Illumio.Rule.consumers.label.href | String | Consumer label URI. | 
| Illumio.Rule.consumers.label_group.href | String | Consumer label group URI. | 
| Illumio.Rule.consumers.actors | String | All workloads. | 
| Illumio.Rule.consumers.virtual_service.href | String | Consumer virtual service URI. | 
| Illumio.Rule.consumers.ip_list.href | String | Consumer ip list URI. | 
| Illumio.Rule.consumers.workload.href | String | Consumer workload URI. | 
| Illumio.Rule.consumers.virtual_server.href | String | Consumer virtual server URI. | 
| Illumio.Rule.consuming_security_principals | String | URI of consuming security principals. | 
| Illumio.Rule.sec_connect | Boolean | Whether a secure connection is established or not. | 
| Illumio.Rule.stateless | Boolean | Whether packet filtering is stateless for the rule or not. | 
| Illumio.Rule.machine_auth | Boolean | Whether machine authentication is enabled or not. | 
| Illumio.Rule.unscoped_consumers | Boolean | Whether the scope for rule consumers is set to all or not. | 
| Illumio.Rule.network_type | String | Network types to which this rule should apply to. | 
| Illumio.Rule.ingress_services.href | String | Array of service URI and port/protocol combinations. | 
| Illumio.Rule.resolve_labels_as.providers | String | Providers resolve labels. | 
| Illumio.Rule.resolve_labels_as.consumers | String | Consumers resolve labels. | 

#### Command example
```!illumio-rule-create ruleset_href=/orgs/1/sec_policy/draft/rule_sets/2292 consumers=ams providers=ams ingress_services=/orgs/1/sec_policy/draft/services/1751```
#### Context Example
```json
{
    "Illumio": {
        "Rule": {
            "consumers": [
                {
                    "actors": "ams"
                }
            ],
            "created_at": "2022-09-19T09:14:36.881Z",
            "created_by": {
                "href": "/users/68"
            },
            "enabled": true,
            "href": "/orgs/1/sec_policy/draft/rule_sets/2292/sec_rules/2463",
            "ingress_services": [
                {
                    "href": "/orgs/1/sec_policy/draft/services/1751"
                }
            ],
            "machine_auth": false,
            "network_type": "brn",
            "providers": [
                {
                    "actors": "ams"
                }
            ],
            "resolve_labels_as": {
                "consumers": [
                    "workloads"
                ],
                "providers": [
                    "workloads"
                ]
            },
            "sec_connect": false,
            "stateless": false,
            "unscoped_consumers": false,
            "update_type": "create",
            "updated_at": "2022-09-19T09:14:36.891Z",
            "updated_by": {
                "href": "/users/68"
            }
        }
    }
}
```

#### Human Readable Output

>### Rule /orgs/1/sec_policy/draft/rule_sets/2292/sec_rules/2463 has been created successfully.
>|Rule HREF|Created At|Updated At|Enabled|Network Type|Ingress Services|
>|---|---|---|---|---|---|
>| /orgs/1/sec_policy/draft/rule_sets/2292/sec_rules/2463 | 19 Sep 2022, 09:14 AM | 19 Sep 2022, 09:14 AM | true | brn | /orgs/1/sec_policy/draft/services/1751 |

