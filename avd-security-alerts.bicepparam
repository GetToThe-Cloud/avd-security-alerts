// =====================================================================
//  Parameters for avd-security-alerts.bicep
//  Replace every placeholder value before deploying.
// =====================================================================

using './avd-security-alerts.bicep'

// The Log Analytics workspace that receives AVD host pool diagnostics,
// Entra ID sign-in logs, the Activity Log, firewall logs and host events.
param workspaceResourceId = '/subscriptions/<subscriptionId>/resourceGroups/<resourceGroup>/providers/Microsoft.OperationalInsights/workspaces/<logAnalyticsWorkspaceName>'

// Who gets the alerts. Ignored if actionGroupResourceId is set.
param alertEmailAddresses = [
  'demo@gettothe.cloud'
]

// Supply an existing action group instead, if you already have one wired
// into your ticketing or on-call tooling.
param actionGroupResourceId = ''

param actionGroupShortName = 'avdsec'
param namePrefix = 'avd-sec'

// The sessionhost subnet, used by the two firewall rules.
param sessionHostSubnetPrefix = '10.0.0.'

// The resource group holding the sessionhost virtual machines.
param sessionHostResourceGroupName = '<sessionhostResourceGroupName'

// Countries your workforce legitimately signs in from. Keep this tight -
// it is what makes the location rules high signal rather than noise.
param allowedCountries = [
  'NL'
  'BE'
  'DE'
  'GB'
]

param tags = {
  workload: 'Azure Virtual Desktop'
  purpose: 'Security monitoring'
  owner: 'Cloud Platform & Engineering'
}

// ---------------------------------------------------------------------
// Rule switches
//
// The two firewall rules ship DISABLED on purpose. Turn them on only once
// your egress rules are tuned, otherwise every missing FQDN is an alert
// and the whole rule set loses credibility in week one.
// ---------------------------------------------------------------------
param enableVmAdminRoleGranted = true
// SecurityEvent is not currently present in law-lz-01. Re-enable after an
// Azure Monitor Agent data collection rule starts collecting events 4732/4733.
param enableLocalAdminChanged = false
param enableSignInWithoutMfa = true
param enableSignInUnexpectedCountry = true
param enableImpossibleTravel = true
param enableFirewallEgressDenied = false
param enableAnomalousDestination = false
param enableFslogixMountFailures = true
param enableStorageKeyAuth = true
param enablePublicIpCreated = true
param enableSessionHostUnhealthy = true
param enableConnectionFailureSpike = true
