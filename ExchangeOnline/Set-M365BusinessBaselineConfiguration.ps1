<#
    .SYNOPSIS
    Basis Konfiguration eines Microsoft 365 Business Premium Mandanten für Exchange Online und Exchange ATP
   
    Alex Fields, Thomas Stensitzki

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE 
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
	
    Version 5.0, 2020-07-10

    Ideen, KOmmentare und Vorschläge bitte an support@granikos.eu 
 
    .LINK  
    http://www.granikos.eu/en/scripts 

    .LINK
    https://www.granikos.eu/de/Blog/PostId/1912/leitfaden-microsoft-365-business-migration-und-konfiguration 

    .DESCRIPTION
    Dieses PowerShell-Skript setzt Basis-Einstellung und Basis-Richtlinien für 
    - Exchange Online
    - Exchange Online Protection 
    - Office 365 Advanced Threat Protection
	
    .NOTES 
    Requirements 
    - Microsoft 365 Business Premium Abonnement
    - Exchange Online Management PowerShell V2 (https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

    Revision History 
    -------------------------------------------------------------------------------- 
    4.0 Erster Community-Release der übersetzten Version
   
    .EXAMPLE
    Set-M365BusinessBaselineConfiguration.ps1
    
#>


###################################################################################################
## NOTE: If the script errors out, you may need to set your local PowerShell execution policy.
## You may also need to run: Enable-OrganizationCustomization in the EXO PowerShell 
## Please define these variables before running this script: 
$MessageColor = 'Green'
$AssessmentColor = 'Yellow'
$ErrorColor = 'Red'
###################################################################################################
$ScriptVersion = '4.0'
$ScriptDir = Split-Path -Path $script:MyInvocation.MyCommand.Path

function Request-Choice {
  [CmdletBinding()]
  param(
    [string]$Caption = 'Really?'
  )

  switch((Get-Culture).IetfLanguageTag) {
    'de-DE' { $choices =  [System.Management.Automation.Host.ChoiceDescription[]]@('&Ja','&Nein') }
    default { $choices =  [System.Management.Automation.Host.ChoiceDescription[]]@('&Yes','&No') }
  }
    
  [int]$defaultChoice = 1

  $choiceReturn = $Host.UI.PromptForChoice($Caption, '', $choices, $defaultChoice)

  return $choiceReturn
}

function Write-MissingCmdlet {
  param(
    [string]$Cmdlet
  )
  Write-Host -ForegroundColor $ErrorColor "Das Cmdlet [$Cmdlet] steht nicht zur Verfügung. Prüfen Sie bitte die Rollenmitgliedschaft des angemeldeten Benutzerkontos."
}

#################################################
## ENABLE UNIFIED AUDIT LOG SEARCH
#################################################

if((Get-Command 'Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue) -ne $null) { 

  $AuditLogConfig = Get-AdminAuditLogConfig

  if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor 'Unified Audit Log Suche ist bereits aktiviert'
  } 
  else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor 'Unified Audit Log ist nicht aktiviert'
  
    if ((Request-Choice -Caption 'Möchten Sie die Auditprotokollierung für Postfächer und das Unfied Audit Log aktivieren?') -eq 0) {
    
      # Aktivierung Unified Audit Protokollierung  
      Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
  
      # Aktivierung Audit Protokollierung für alle EXO Postfächer
      $null = Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true
   
      Write-Host 
      Write-Host -ForegroundColor $MessageColor 'Unified Audit Log Suche und die Postfach-Auditprotokollierung sind aktiviert' 
    } 
    else {
      Write-Host 
      Write-Host -ForegroundColor $AssessmentColor 'Unified Audit Log wird nicht aktiviert'
    }
    
    Write-Host
    
  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Get-AdminAuditLogConfig'
}

 
#################################################
## CHECK TO ENSURE MODERN AUTH IS ENABLED
#################################################

if((Get-Command 'Get-OrganizationConfig' -ErrorAction SilentlyContinue) -ne $null) { 

  $OrgConfig = Get-OrganizationConfig 
  
  if ($OrgConfig.OAuth2ClientProfileEnabled) {
  
    Write-Host 
    Write-Host -ForegroundColor $MessageColor 'Modern Authentication für Exchange Online ist bereits aktiviert'
  } 
  else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor 'Modern Authentication für Exchange Online ist nicht aktiviert'
    Write-Host 
  
    if ((Request-Choice -Caption 'Möchten Sie Modern Authentication für Exchange Online jetzt aktivieren?') -eq 0) {
      
      Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
      Write-Host 
      Write-Host -ForegroundColor $MessageColor 'Modern Authentication ist jetzt aktiviert'
    } 
    else {
      Write-Host
      Write-Host -ForegroundColor $AssessmentColor 'Modern Authentication wird nicht aktiviert'
    }
    
    Write-Host
    
  }
     
  #################################################
  ## BLOCK BASIC AUTH
  #################################################
  
  if ($OrgConfig.DefaultAuthenticationPolicy -eq $null -or $OrgConfig.DefaultAuthenticationPolicy -eq '') {
  
    Write-Host 
    Write-Host -ForegroundColor $MessageColor 'Es existiert keine Standard-Authentifizierungsrichtlinie'
    Write-Host -ForegroundColor $MessageColor "HINWEIS: Wenn Sie Sicherheitsstandards oder Bedingten Zugriff nutzen, ist dies nicht erforderlich"
  
    if ((Request-Choice -Caption 'Möchten Sie unsichere Anmeldeverfahren mit einer Authentifizierungsrichtlinie blockieren?') -eq 0) {

      # Name der Richtlinie
      $PolicyName = 'Blockierung Basic Auth - M365Skript'
      $CheckPolicy = Get-AuthenticationPolicy | Where-Object {$_.Name -contains $PolicyName}

      if (!$CheckPolicy) {
        # Erstellung einer neuen Richtlinie
        New-AuthenticationPolicy -Name $PolicyName
        Write-Host
        Write-Host -ForegroundColor $MessageColor ('Richtlinie [{0}] wurde erstellt' -f $PolicyName)
      } 
      else {
        Write-Host
        Write-Host  -ForegroundColor $MessageColor ('Richtlinie [{0}] existiert bereits' -f $PolicyName)
      }
      
      # Setzen der Standard-Authentifizierungsrichtlinie
      Set-OrganizationConfig -DefaultAuthenticationPolicy $PolicyName
      
      Write-Host
      Write-Host -ForegroundColor $MessageColor ('Richtlinie [{0}] wurde als organisationsweite Standard-Authentifizierungsrichtlinie konfiguriert' -f $PolicyName)
      Write-Host -ForegroundColor $MessageColor 'In den Kommentaren dieses Skriptes finden Sie Informationen zur weiteren Anpassung der Richtlinie'
      Write-Host
    } 
    else {
      Write-Host
      Write-Host  -ForegroundColor $AssessmentColor ('Richtlinie [{0}] wird nicht als Standard-Authentifizierungsrichtlinie konfiguriert' -f $PolicyName)
      Write-Host
    }
  } 
  else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor 'Es existiert bereits eine Standardrichtlinie. Es werden keine Änderunge vorgenommen. Die Standardrichtlinie ist:'
    Write-Host
    $OrgConfig.DefaultAuthenticationPolicy
    Write-Host 
  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Get-OrganizationConfig'
}

## OPTIONAL: 
## Create and assign the 'Block Basic Auth' policy explicitly to all users:
## New-AuthenticationPolicy "Block Basic Auth"
## Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"

## OPTIONAL: 
## Create additional authentication policies for allowing exceptions for basic authentication (e.g. for service accounts)

## EXAMPLE:
## New-AuthenticationPolicy "Allow Basic Auth for <ServiceName>"

## Then use Set-AuthenticationPolicy to allow basic auth for one or more of these protocols:
## AllowBasicAuthActiveSync           
## AllowBasicAuthAutodiscover        
## AllowBasicAuthImap                 
## AllowBasicAuthMapi                 
## AllowBasicAuthOfflineAddressBook   
## AllowBasicAuthOutlookService       
## AllowBasicAuthPop                  
## AllowBasicAuthReportingWebServices 
## AllowBasicAuthRest                 
## AllowBasicAuthRpc                  
## AllowBasicAuthSmtp                 
## AllowBasicAuthWebServices          
## AllowBasicAuthPowershell           

## Example below enables basic auth for IMAP: 
## Set-AuthenticationPolicy "Allow Basic Auth for IMAP"  -AllowBasicAuthImap

## To assign the exception policy to an account use:
## $ExceptionUser = username@domain.com
## Set-User -Identity $ExceptionUser -AuthenticationPolicy "Allow Basic Auth Exceptions"


#################################################
## DISABLE AUTOMATIC FORWARDING 
#################################################

if((Get-Command 'Get-RemoteDomain' -ErrorAction SilentlyContinue) -ne $null) { 

  $RemoteDomainDefault = Get-RemoteDomain Default 

  if ($RemoteDomainDefault.AutoForwardEnabled) {
  
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor 'Die automatische Weiterleitung von E-Mails an externe Empfänger ist aktuell erlaubt.'
    Write-Host 

    if ((Request-Choice -Caption 'Soll die automatische Weiterleitung an externe Empfänger unterbunden werden?') -eq 0) {
  
      ## DENY AUTOFORWARD ON THE DEFAULT REMOTE DOMAIN (*) 
      Set-RemoteDomain Default -AutoForwardEnabled $false
    
      ## ALSO DENY AUTO-FORWARDING FROM MAILBOX RULES VIA TRANSPORT RULE WITH REJECTION MESSAGE
      $TransportRuleName = "Blockierung externer Weiterleitungen"
      $rejectMessageText = 'Die automatische Weiterleitung von E-Mail-Nachrichten an externe Empfänger ist untersagt. Für weitere Informationen wenden Sie sich bitte an das Helpdesk.'
      
      $ExternalForwardRule = Get-TransportRule | Where-Object {$_.Identity -contains $TransportRuleName}
    
      if (!$ExternalForwardRule) {
        Write-Host -ForegroundColor $MessageColor 'Transportregel zur Blockierung automatischer Weiterleitungen wurde nicht gefunden. Die Regel wird erstellt.'
        New-TransportRule -name $TransportRuleName -Priority 1 -SentToScope NotInOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText
      } 
      else {
        Write-Host -ForegroundColor $MessageColor 'Die Transportregel zur Blockierung automatischer Weiterleitungen existiert bereits.'
      } 
      Write-Host 
      Write-Host -ForegroundColor $MessageColor 'Die automatische Weiterleitung an externe Empfänger ist deaktiviert.'        
    } 
    else {
      Write-Host
      Write-Host -ForegroundColor $AssessmentColor 'Die automatische Weiterleitung an externe Empfänger wird nicht deaktiviert'
    }
  
    ## EXPORT LIST OF FORWARDERS TO CSV
    Write-Host    
  
    if ((Request-Choice -Caption 'Soll eine Liste der eventuell betroffenen Postfächer als CSV-Datei exportiert werden?') -eq 0) {
  
      ## Collect existing mailbox forwarding into CSV files as DomainName-MailboxForwarding.csv and DomainName-InboxRules.csv
      Write-Host 
      Write-Host -ForegroundColor $AssessmentColor 'Export der Postfachweiterleitungen und Posteingangsregeln für automatische Weiterleitungen'
    
      $DefaultDomainName = Get-AcceptedDomain | Where-Object Default -EQ True
        
      Get-Mailbox -ResultSize Unlimited -Filter {(RecipientTypeDetails -ne 'DiscoveryMailbox') -and ((ForwardingSmtpAddress -ne $null) -or (ForwardingAddress -ne $null))} | Select-Object -Property Identity,ForwardingSmtpAddress,ForwardingAddress | Export-Csv -Path (Join-Path -Path $ScriptDir -ChildPath ('{0}-MailboxForwarding.csv' -f $DefaultDomainName)) -Append -Encoding UTF8 -Delimiter ';'
    
      foreach ($a in (Get-Mailbox -ResultSize Unlimited |Select-Object -Property PrimarySMTPAddress)) {
        Get-InboxRule -Mailbox $a.PrimarySMTPAddress | Where-Object{($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.DeleteMessage -eq $true) -or ($_.RedirectTo -ne $null)} |Select-Object -Property Name,Identity,ForwardTo,ForwardAsAttachmentTo, RedirectTo, DeleteMessage | Export-Csv -Path (Join-Path -Path $ScriptDir -ChildPath ('{0}-InboxRules.csv' -f $DefaultDomainName)) -Append -Encoding UTF8 -Delimiter ';' 
      }
    
      Write-Host 
      Write-Host -ForegroundColor $AssessmentColor "Prüfen Sie nach Abschluss des Skriptes die CSV-Dateien im Verzeichnis $ScriptDir auf eventuelle betroffene Anwender dieser Änderung."
    } 
    else {
      Write-Host 
      Write-Host  -ForegroundColor $MessageColor 'Führen Sie das Skript erneut aus, wenn Sie eine Übersicht der Postfächer und Posteingangsregeln mit automatischer Weiterleitung exportieren möchten.'
    }
  } 
  else {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor 'Die automatische Weiterleitung für Remote-Domänen ist bereits unterbunden.'
  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Get-RemoteDomain'
}

#################################################
## RESET THE DEFAULT ANTISPAM SETTINGS
#################################################

if((Get-Command 'Set-HostedContentFilterPolicy' -ErrorAction SilentlyContinue) -ne $null) { 

  Write-Host 

  if ((Request-Choice -Caption 'Möchten Sie die empfohlenen Standard-Einstellungen für die Anti-Spam-Filterung konfigurieren?') -eq 0) {
  
    # Definition der Standard AntiSpam-Richtlinie
    $HostedContentPolicyParam = @{
      'bulkspamaction' =  'MoveToJMF';
      'bulkthreshold' =  '6';
      'highconfidencespamaction' =  'quarantine';
      'inlinesafetytipsenabled' = $true;
      'markasspambulkmail' = 'on';
      'enablelanguageblocklist' = $false;
      'enableregionblocklist' = $false;
      'increasescorewithimagelinks' = 'off'
      'increasescorewithnumericips' = 'off'
      'increasescorewithredirecttootherport' = 'off'
      'increasescorewithbizorinfourls' = 'off';
      'markasspamemptymessages' ='off';
      'markasspamjavascriptinhtml' = 'off';
      'markasspamframesinhtml' = 'off';
      'markasspamobjecttagsinhtml' = 'off';
      'markasspamembedtagsinhtml' ='off';
      'markasspamformtagsinhtml' = 'off';
      'markasspamwebbugsinhtml' = 'off';
      'markasspamsensitivewordlist' = 'off';
      'markasspamspfrecordhardfail' = 'off';
      'markasspamfromaddressauthfail' = 'off';
      'markasspamndrbackscatter' = 'off';
      'phishspamaction' = 'quarantine';
      'phishzapenabled' = $true;
      'spamaction' = 'MoveToJMF';
      'spamzapenabled' = $true;
      'EnableEndUserSpamNotifications' = $true;
      'EndUserSpamNotificationFrequency' = 1;
      'QuarantineRetentionPeriod' = 30
    }
    
    # Filter-Richtlinie DEFAULT anpassen
    Set-HostedContentFilterPolicy Default @HostedContentPolicyParam -MakeDefault
    
    Write-Host
    Write-Host -ForegroundColor $MessageColor 'Die Standard AntiSpam-Richtlinie wurde auf die empfohlenen Einstellungen angepasst.'
    Write-Host 
  
    if ((Request-Choice -Caption 'Sollen benutzerdefinierte AntiSpam-Regeln deaktiviert werden, so dass nur die Standard-Richtlinie aktiv ist?') -eq 0) {
      
      # AntiSpam-Regeln deaktivieren
      Get-HostedContentFilterRule | Disable-HostedContentFilterRule
      
      Write-Host
      Write-Host -ForegroundColor $MessageColor 'Alle beutzerdefinierten AntiSpam-Regeln wurden deaktiviert, jedoch nicht gelöscht.'
    } 
    else {
      Write-Host 
      Write-Host -ForegroundColor $AssessmentColor 'Es wurden keine benutzerdefinierten Anti-Spam-Regeln deaktiviert.'
    }
    
  } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor 'Die Standard AntiSpam-Richtlinie wurde nicht verändert.'
  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Set-HostedContentFilterPolicy'
}


#################################################
## RESET DEFAULT ANTIMALWARE SETTINGS
#################################################

if((Get-Command 'Set-MalwareFilterPolicy' -ErrorAction SilentlyContinue) -ne $null) { 

  Write-Host 

  if ((Request-Choice -Caption 'Soll die Standard Malware Filter-Richtlinie mit den empfohlenen Einstellungen konfiguriert werden?') -eq 0) {
    Write-Host 
  
    # E-Mail-Adresse abfragen
    $AlertAddress= Read-Host -Prompt 'An welche E-Mail-Adresse sollen Warnungen über Malware-Vorfälle gesendet werden?'
  
    ## Anpassung der Standard Malware Filter-Richtlinie
    $MalwarePolicyParam = @{
      'Action' =  'DeleteMessage';
      'EnableFileFilter' =  $true;
      'EnableInternalSenderAdminNotifications' = $true;
      'InternalSenderAdminAddress' =  $AlertAddress;
      'EnableInternalSenderNotifications' =  $false;
      'EnableExternalSenderNotifications' = $false;
      'Zap' = $true
    }
  
    # Standard Malware-Richtlinie konfigurieren
    Set-MalwareFilterPolicy Default @MalwarePolicyParam -MakeDefault
    
    Write-Host 
    Write-Host -ForegroundColor $MessageColor 'Die Standard Malware Filter-Richtlinie wurde mit den emfpohlenen Einstellungen konfiguriert.'
    Write-Host 
    
    if ((Request-Choice -Caption 'Sollen benutzerdefinierte Malware Filterregeln deaktiviert werden, so dass nur die Standard-Richtlinie aktiv ist?') -eq 0) {
    
      # Benutzerdefinierte Regeln deaktivieren
      Get-MalwareFilterRule | Disable-MalwareFilterRule
    
      Write-Host
      Write-Host -ForegroundColor $MessageColor 'Alle benutzerdefinierten Malware Filterregeln wurden desktiviert, jedoch nicht gelöscht.'
    } else {
      Write-Host 
      Write-Host -ForegroundColor $AssessmentColor 'Es wurden keine benutzerdefinierten Regeln deaktiviert.'
    }
    
  } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor 'Die Standard Malware Filter-Richtlinie wurde nicht verändert.'
  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Set-MalwareFilterPolicy'
}

#################################################
## RESET OUTBOUND SPAM FILTER
#################################################
if((Get-Command 'Set-HostedOutboundSpamFilterPolicy' -ErrorAction SilentlyContinue) -ne $null) { 

  Write-Host 

  if ((Request-Choice -Caption 'Soll die AntiSPam-Filterrichtlinie für ausgehende E-Mail-Nachrichten mit den empfohlenen Einstellungen konfiguriert werden?') -eq 0) {
  
    if ($AlertAddress -eq $null -or $AlertAddress -eq '') {
      
      $AlertAddress = Read-Host -Prompt 'An welche E-Mail-Adresse sollen Warnungen über ausgehende Spam-Vorfälle gesendet werden?'
      
      # Einstellungen der Antipam-Richtlinie
      $OutboundPolicyParam = @{
        'Identity' = 'Default';
        'RecipientLimitExternalPerHour' = 500;
        'RecipientLimitInternalPerHour' = 1000;
        'RecipientLimitPerDay' = 1000;
        'ActionWhenThresholdReached' = BlockUser;
        'notifyoutboundspam' = $true;
        'NotifyOutboundSpamRecipients' = $AlertAddress
      }
      
      # Setzen der Richtlinie
      Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam
      
      Write-Host
      Write-Host -ForegroundColor $MessageColor 'Die AntiSpam-Filterrichtlinie für ausgehende E-Mail-Nachrichten wurde mit den empfohlenen Einstellungen konfiguriert.'
      
    } 
    else {
      # Standard
      $OutboundPolicyParam = @{
        'identity' = 'Default';
        'notifyoutboundspam' = $true;
        'NotifyOutboundSpamRecipients' = $AlertAddress
      }
      
      Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam
      Write-Host
      Write-Host -ForegroundColor $MessageColor 'Die AntiSpam-Filterrichtlinie für ausgehende E-Mail-Nachrichten wurde auf die Standard-Einstellungen zurückgesetzt.'
    }
  } 
  else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor 'Die AntiSpam-Filterrichtlinie für ausgehende E-Mail-Nachrichten wurde nicht verändert.'
  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Set-HostedOutboundSpamFilterPolicy'
}

#################################################
## CONFIGURE OFFICE 365 ATP SETTINGS
#################################################
if((Get-Command 'Set-HostedOutboundSpamFilterPolicy' -ErrorAction SilentlyContinue) -ne $null) { 

  Write-Host

  if ((Request-Choice -Caption 'Soll Office 365 ATP mit den empfohlenen Einstellungen konfiguriert werden?') -eq 0) {

    $AcceptedDomains = Get-AcceptedDomain
    $RecipientDomains = $AcceptedDomains.DomainName

    Write-Host -ForegroundColor $MessageColor 'Konfiguration der ATP-Richtlinie für Office 365...'

    ## Konfiguration der Standard ATP Richtlinie für Office 365
    ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/set-atppolicyforo365?view=exchange-ps
  
    $AtpPolicyForO365Param=@{
      'EnableATPForSPOTeamsODB' =  $true;
      #'EnableSafeLinksForClients' = $true;
      'EnableSafeLinksForO365Clients' = $true;
      'EnableSafeDocs' = $false
      'TrackClicks' = $true;
      'AllowClickThrough' = $false
    }

    Set-AtpPolicyForO365 @AtpPolicyForO365Param

    Write-Host -ForegroundColor $MessageColor 'Die Standard ATP-Richtlinie für Office 365 wurde konfiguriert.'

    Write-Host -ForegroundColor $MessageColor 'Erstellung einer Safe Links Basis-Richtlinie...'
	
    ## SafeLinks Richtlinie
    ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinkspolicy?view=exchange-ps

    $SafeLinksPolicyParam=@{
      'Name' = 'Basis-Richtlinie Sichere Links- M365 Skript';
      'AdminDisplayName' = 'Basis-Richtlinie Sichere Links- M365 Skript';
      'DoNotAllowClickThrough' =  $true;
      'DoNotTrackUserClicks' = $false;
      'DeliverMessageAfterScan' = $true;
      'EnableForInternalSender' = $true;
      'ScanUrls' = $true;
      'TrackClicks' = $true;
      'IsEnabled' = $true
    }

    New-SafeLinksPolicy @SafeLinksPolicyParam 

    ## SafeLinks Regeln
    ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinksrule?view=exchange-ps

    $SafeLinksRuleParam = @{
      'Name' = 'Basis-Regel Sichere Links - M365 Skript';
      'SafeLinksPolicy' = 'Basis-Richtlinie Sichere Links- M365 Skript';
      'RecipientDomainIs' = $RecipientDomains;
      'Enabled' = $true;
      'Priority' = 0
    }

    New-SafeLinksRule @SafeLinksRuleParam

    Write-Host -ForegroundColor $MessageColor 'Die Safe Links Basis-Richtlinie wurde erstellt.'

    Write-Host -ForegroundColor $MessageColor 'Erstellung der Basis-Richtlinie für sichere Anhänge...'

    ## SafeAttachments Richtlinie
    ## Action options = Block | Replace | Allow | DynamicDelivery (Block is the recommended action)
    ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safeattachmentpolicy?view=exchange-ps

    $SafeAttachmentPolicyParam=@{
      'Name' = 'Basis-Richtlinie Sichere Anhänge - M365 Skript';
      'AdminDisplayName' = 'Basis-Richtlinie Sichere Anhänge - M365 Skript';
      'Action' =  'Block';
      'ActionOnError' = $false;
      'Enable' = $true;
      'Redirect' = $false
    }

    New-SafeAttachmentPolicy @SafeAttachmentPolicyParam

    ## Create the SafeAttachments Rule 
    ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safeattachmentrule?view=exchange-ps

    $SafeAttachRuleParam=@{
      'Name' = 'Basis-Regel Sichere Anhänge - M365 Skript';
      'SafeAttachmentPolicy' = 'Basis-Richtlinie Sichere Anhänge - M365 Skript';
      'RecipientDomainIs' = $RecipientDomains;
      'Enabled' = $true;
      'Priority' = 0
    }

    New-SafeAttachmentRule @SafeAttachRuleParam

    Write-Host -ForegroundColor $MessageColor 'Die Basis-Richtlinie für sichere Anhänge wurde erstellt.'

    Write-Host -ForegroundColor $MessageColor 'Erstellung der Anti-Phish Basis-Richtlinie...'

    ## Create the Anti-Phish policy 
    ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishpolicy?view=exchange-ps

    $PhishPolicyParam=@{
      ##'Name' = "AntiPhish Baseline Policy";
      ##'AdminDisplayName' = "AntiPhish Baseline Policy";
      'AuthenticationFailAction' =  'Quarantine';
      'EnableAntispoofEnforcement' = $true;
      'Enabled' = $true;
      'EnableMailboxIntelligence' = $true;
      'EnableMailboxIntelligenceProtection' = $true;
      'MailboxIntelligenceProtectionAction' = 'Quarantine';
      'EnableOrganizationDomainsProtection' = $true;
      'EnableSimilarDomainsSafetyTips' = $true;
      'EnableSimilarUsersSafetyTips' = $true;
      'EnableTargetedDomainsProtection' = $false;
      ##'TargetedDomainsToProtect' = $RecipientDomains;
      'EnableTargetedUserProtection' = $false;
      ##'TargetedUsersToProtect' = $TargetedUsersToProtect;
      'EnableUnusualCharactersSafetyTips' = $true;
      'PhishThresholdLevel' = 2;
      'TargetedDomainProtectionAction' =  'Quarantine';
      'TargetedUserProtectionAction' =  'Quarantine'
    }

    Set-AntiPhishPolicy -Identity 'Office365 AntiPhish Default' @PhishPolicyParam


    <# Ignore this section unless you are attempting to create custom rules
        ## Get-AntiPhishRule | Remove-AntiPhishRule
        ## Get-AntiPhishPolicy | Where-Object IsDefault -eq $false | Set-AntiPhishPolicy -Enabled $false 
        ## Create the AntiPhish rule
        ## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishrule?view=exchange-ps
	
        $PhishRuleParam = @{
        'Name' = "AntiPhish Baseline";
        'AntiPhishPolicy' = "AntiPhish Baseline Policy"; 
        'RecipientDomainis' = $RecipientDomains;
        'Enabled' = $true;
        'Priority' = 0
        }

        New-AntiPhishRule @PhishRuleParam
    #>

    Write-Host -foregroundcolor green 'Die Anti Phish Basis-Richtlinie wurde erstellt.'

    write-host -foregroundcolor green 'Office 365 ATP Basiskonfiguration wurde abgeschlossen.'

  } else {

    Write-Host
    Write-Host -ForegroundColor $AssessmentColor 'Office 365 ATP-Funktionen wurde nicht verändert.'

  }
}
else {
  Write-MissingCmdlet -Cmdlet 'Set-AtpPolicyForO365'
}
###################################################################################################
## THIS CONCLUDES THE SCRIPT
