// =====================================================================
//  Azure Virtual Desktop - Security Alert Rules
//  Companion deployment for the GetToTheCloud AVD security series
//  Author: Alex ter Neuzen
//
//  Deploys an action group and a set of Azure Monitor scheduled query
//  alert rules that watch the controls described in Parts I to III.
//
//  Scope: resource group
//  Deploy: az deployment group create \
//            --resource-group rg-avd-monitoring \
//            --template-file avd-security-alerts.bicep \
//            --parameters @avd-security-alerts.bicepparam
//
//  Every rule can be switched off individually with the enable* flags,
//  because a rule you have not tuned yet is worse than no rule at all.
// =====================================================================

targetScope = 'resourceGroup'

@description('Location for the alert rule resources.')
param location string = resourceGroup().location

@description('Resource ID of the Log Analytics workspace the AVD, Entra ID, Activity and firewall diagnostics land in.')
param workspaceResourceId string

@description('Email addresses that receive the alerts. Replaced by an existing action group if actionGroupResourceId is supplied.')
param alertEmailAddresses array = []

@description('Optional. Resource ID of an EXISTING action group. Leave empty to create one from alertEmailAddresses.')
param actionGroupResourceId string = ''

@description('Short name for the action group. Twelve characters maximum.')
@maxLength(12)
param actionGroupShortName string = 'avdsec'

@description('Prefix applied to every alert rule name.')
param namePrefix string = 'avd-sec'

@description('IPv4 prefix of the sessionhost subnet, used by the firewall egress rules. Example: 10.10.20.')
param sessionHostSubnetPrefix string = '10.10.20.'

@description('Name of the resource group holding the sessionhost virtual machines.')
param sessionHostResourceGroupName string = 'rg-avd-sessionhosts'

@description('ISO country codes your workforce legitimately signs in from.')
param allowedCountries array = [
  'NL'
  'BE'
  'DE'
  'GB'
]

@description('Tags applied to every resource.')
param tags object = {
  workload: 'Azure Virtual Desktop'
  purpose: 'Security monitoring'
}

// --- Individual rule switches -----------------------------------------
param enableVmAdminRoleGranted bool = true
param enableLocalAdminChanged bool = true
param enableSignInWithoutMfa bool = true
param enableSignInUnexpectedCountry bool = true
param enableImpossibleTravel bool = true
param enableFirewallEgressDenied bool = false // enable only after egress rules are tuned
param enableAnomalousDestination bool = false // enable only after egress rules are tuned
param enableFslogixMountFailures bool = true
param enableStorageKeyAuth bool = true
param enablePublicIpCreated bool = true
param enableSessionHostUnhealthy bool = true
param enableConnectionFailureSpike bool = true

// =====================================================================
//  Well-known identifiers
// =====================================================================

// Azure built-in role definition - Virtual Machine Administrator Login
var vmAdminLoginRoleId = '1c0163c0-47e6-4577-8991-ea5c82e286e4'

// Application IDs used on the AVD authentication path. Identical in every tenant.
var avdAppIds = [
  'a4a365df-50f1-4397-bc59-1a1564b8bb9c' // Microsoft Remote Desktop
  '270efc09-cd0d-444b-a71f-39af4910ec45' // Windows Cloud Login
  '9cdead84-a844-4324-93f2-b2e6bb768d07' // Azure Virtual Desktop
]

var avdAppIdList = '"${join(avdAppIds, '","')}"'
var allowedCountryList = '"${join(allowedCountries, '","')}"'

// Bicep multi-line strings are verbatim - they do not interpolate - so the
// queries below carry __TOKENS__ that are substituted in the rule loop.

// =====================================================================
//  Action group
// =====================================================================

resource createdActionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (empty(actionGroupResourceId)) {
  name: '${namePrefix}-ag'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: actionGroupShortName
    enabled: true
    emailReceivers: [
      for (address, i) in alertEmailAddresses: {
        name: 'email${i}'
        emailAddress: address
        useCommonAlertSchema: true
      }
    ]
  }
}

var effectiveActionGroupId = empty(actionGroupResourceId) ? createdActionGroup.id : actionGroupResourceId

// =====================================================================
//  Rule definitions
// =====================================================================

var rules = [
  {
    enabled: enableVmAdminRoleGranted
    name: 'vm-admin-login-granted'
    displayName: 'AVD | Virtual Machine Administrator Login was granted'
    description: 'Somebody assigned the Virtual Machine Administrator Login role, which makes the assignee a local administrator on the sessionhosts in scope. Verify the assignment was intended and time-bound.'
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    threshold: 0
    query: '''
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue in ("Success", "Succeeded")
| extend RequestBody = tostring(parse_json(tostring(parse_json(Properties).requestbody)))
| where RequestBody has "__VM_ADMIN_ROLE_ID__"
| extend PrincipalId = tostring(parse_json(RequestBody).Properties.PrincipalId)
| extend AssignedScope = tostring(parse_json(RequestBody).Properties.Scope)
| project TimeGenerated, Caller, CallerIpAddress, PrincipalId, AssignedScope, _ResourceId
'''
  }
  {
    enabled: enableLocalAdminChanged
    name: 'local-admin-group-changed'
    displayName: 'AVD | Local Administrators group changed on a sessionhost'
    description: 'Membership of the local Administrators group changed on a sessionhost. On a fleet with no standing local administrators this is either an undocumented admin action or privilege escalation in progress.'
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT10M'
    threshold: 0
    query: '''
SecurityEvent
| where EventID in (4732, 4733)
| where TargetAccount has "Administrators" or MemberName has "Administrators"
| extend Action = iff(EventID == 4732, "Added to local group", "Removed from local group")
| project TimeGenerated, Computer, Action, TargetAccount, MemberName, SubjectAccount, Activity
'''
  }
  {
    enabled: enableSignInWithoutMfa
    name: 'signin-without-mfa'
    displayName: 'AVD | Successful sign-in without multi-factor authentication'
    description: 'A successful sign-in against an AVD authentication application satisfied only a single factor. This usually means a Conditional Access policy covers one of the AVD applications but not all of them.'
    severity: 2
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
let AvdAppIds = dynamic([__AVD_APP_IDS__]);
SigninLogs
| where AppId in (AvdAppIds)
| where ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignInCount = count(), Locations = make_set(Location, 10), IPs = make_set(IPAddress, 10)
    by UserPrincipalName, AppDisplayName
'''
  }
  {
    enabled: enableSignInUnexpectedCountry
    name: 'signin-unexpected-country'
    displayName: 'AVD | Sign-in from an unexpected country'
    description: 'A successful AVD sign-in originated from a country outside the expected list. Tune the allowed country list to your actual workforce before relying on this rule.'
    severity: 1
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
let AllowedCountries = dynamic([__ALLOWED_COUNTRIES__]);
let AvdAppIds = dynamic([__AVD_APP_IDS__]);
SigninLogs
| where AppId in (AvdAppIds)
| where ResultType == 0
| where isnotempty(Location) and Location !in (AllowedCountries)
| extend City = tostring(parse_json(tostring(LocationDetails)).city)
| project TimeGenerated, UserPrincipalName, AppDisplayName, Location, City, IPAddress, UserAgent
'''
  }
  {
    enabled: enableImpossibleTravel
    name: 'impossible-travel'
    displayName: 'AVD | Geographically incompatible sign-ins for one user'
    description: 'One user signed in successfully to AVD from more than one country inside a window too short to have travelled it. Entra ID Protection does this better where you are licensed for it.'
    severity: 1
    evaluationFrequency: 'PT30M'
    windowSize: 'PT6H'
    threshold: 0
    query: '''
let AvdAppIds = dynamic([__AVD_APP_IDS__]);
SigninLogs
| where AppId in (AvdAppIds)
| where ResultType == 0
| where isnotempty(Location)
| summarize CountryCount = dcount(Location), Countries = make_set(Location, 10), IPs = make_set(IPAddress, 10),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where CountryCount > 1
| extend WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where WindowMinutes < 240
'''
  }
  {
    enabled: enableFirewallEgressDenied
    name: 'egress-denied-spike'
    displayName: 'AVD | Sessionhost outbound traffic denied by the firewall'
    description: 'A sessionhost generated an unusual volume of denied outbound connections. Leave this rule disabled until your egress rules are tuned, otherwise every missing FQDN produces an alert.'
    severity: 3
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
AZFWApplicationRule
| where Action == "Deny"
| where SourceIp startswith "__SUBNET_PREFIX__"
| summarize DenyCount = count(), Targets = make_set(Fqdn, 20) by SourceIp, Protocol
| where DenyCount > 20
'''
  }
  {
    enabled: enableAnomalousDestination
    name: 'anomalous-destination'
    displayName: 'AVD | One sessionhost reaching a destination its siblings never reach'
    description: 'Sessionhosts built from a common image behave almost identically. A destination contacted by exactly one host over a day is worth a look. Requires a tuned egress baseline.'
    severity: 2
    evaluationFrequency: 'PT1H'
    windowSize: 'P1D'
    threshold: 0
    query: '''
AZFWApplicationRule
| where SourceIp startswith "__SUBNET_PREFIX__"
| where isnotempty(Fqdn)
| summarize HostCount = dcount(SourceIp), Hosts = make_set(SourceIp, 5), Hits = count() by Fqdn
| where HostCount == 1 and Hits > 5
'''
  }
  {
    enabled: enableFslogixMountFailures
    name: 'fslogix-mount-failures'
    displayName: 'AVD | Profile container mount failures across multiple users'
    description: 'A spike in FSLogix container mount failures affecting several hosts at once. Either the storage path is broken or something is encrypting the containers. Both are incidents.'
    severity: 1
    evaluationFrequency: 'PT10M'
    windowSize: 'PT30M'
    threshold: 0
    query: '''
Event
| where Source has "FSLogix"
| where EventLevelName in ("Error", "Warning")
| where RenderedDescription has_any ("failed to attach", "cannot attach", "load profile", "mount")
| summarize FailureCount = count(), AffectedHosts = dcount(Computer), Hosts = make_set(Computer, 20)
    by bin(TimeGenerated, 10m)
| where FailureCount > 10 or AffectedHosts > 3
'''
  }
  {
    enabled: enableStorageKeyAuth
    name: 'storage-key-authentication'
    displayName: 'AVD | Profile storage accessed with an account key'
    description: 'The FSLogix storage account was accessed using a shared account key rather than identity-based authentication. A storage key is a shared, non-attributable credential that reaches every profile at once.'
    severity: 2
    evaluationFrequency: 'PT30M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
StorageFileLogs
| where AuthenticationType == "AccountKey"
| summarize Operations = count(), Callers = make_set(CallerIpAddress, 10), OperationTypes = make_set(OperationName, 10)
    by AccountName
'''
  }
  {
    enabled: enablePublicIpCreated
    name: 'public-ip-created'
    displayName: 'AVD | Public IP address created in the sessionhost scope'
    description: 'A public IP address was created in the sessionhost resource group. AVD uses a reverse connect model and sessionhosts never need inbound connectivity. Pair this rule with an Azure Policy deny.'
    severity: 2
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
AzureActivity
| where OperationNameValue =~ "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE"
| where ActivityStatusValue in ("Success", "Succeeded", "Start")
| where _ResourceId has "/resourceGroups/__SESSIONHOST_RG__"
| project TimeGenerated, Caller, CallerIpAddress, ActivityStatusValue, _ResourceId
'''
  }
  {
    enabled: enableSessionHostUnhealthy
    name: 'sessionhost-unhealthy'
    displayName: 'AVD | Sessionhost unhealthy or not accepting sessions'
    description: 'A sessionhost is registered but unhealthy or not accepting new sessions. This is the classic symptom of an over-tight egress policy or a private DNS zone resolving somewhere unreachable.'
    severity: 2
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
WVDAgentHealthStatus
| summarize arg_max(TimeGenerated, *) by SessionHostName
| where Status != "Available" or tobool(AllowNewSessions) == false
| project TimeGenerated, SessionHostName, Status, UpgradeState, LastHeartBeat, AllowNewSessions
'''
  }
  {
    enabled: enableConnectionFailureSpike
    name: 'connection-failure-spike'
    displayName: 'AVD | Spike in failed connections'
    description: 'An unusual number of connection errors across the environment. You will usually see the operational symptom of a security or network change before you see the security event itself.'
    severity: 3
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    threshold: 0
    query: '''
WVDErrors
| summarize ErrorCount = count(), AffectedUsers = dcount(UserName), Sources = make_set(Source, 10), Codes = make_set(CodeSymbolic, 10)
    by bin(TimeGenerated, 15m)
| where ErrorCount > 25 or AffectedUsers > 5
'''
  }
]

// =====================================================================
//  Alert rules
// =====================================================================

resource alertRules 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = [
  for rule in rules: if (rule.enabled) {
    name: '${namePrefix}-${rule.name}'
    location: location
    tags: tags
    properties: {
      displayName: rule.displayName
      description: rule.description
      severity: rule.severity
      enabled: true
      evaluationFrequency: rule.evaluationFrequency
      windowSize: rule.windowSize
      scopes: [
        workspaceResourceId
      ]
      criteria: {
        allOf: [
          {
            query: replace(replace(replace(replace(replace(rule.query, '__AVD_APP_IDS__', avdAppIdList), '__ALLOWED_COUNTRIES__', allowedCountryList), '__SUBNET_PREFIX__', sessionHostSubnetPrefix), '__SESSIONHOST_RG__', sessionHostResourceGroupName), '__VM_ADMIN_ROLE_ID__', vmAdminLoginRoleId)
            timeAggregation: 'Count'
            operator: 'GreaterThan'
            threshold: rule.threshold
            failingPeriods: {
              numberOfEvaluationPeriods: 1
              minFailingPeriodsToAlert: 1
            }
          }
        ]
      }
      autoMitigate: false
      actions: {
        actionGroups: [
          effectiveActionGroupId
        ]
        customProperties: {
          series: 'GetToTheCloud AVD security'
          control: rule.name
        }
      }
    }
  }
]

// =====================================================================
//  Outputs
// =====================================================================

output actionGroupId string = effectiveActionGroupId
output deployedRuleCount int = length(filter(rules, r => r.enabled))
output deployedRuleNames array = map(filter(rules, r => r.enabled), r => '${namePrefix}-${r.name}')
