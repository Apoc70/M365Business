## Description:
## This script can be used to enable modern auth and also block basic authentication in Exchange Online
## WARNING: This script will block older clients from connecting to Exchange Online
## Prerequisites:
## The tenant will require any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.

$MessageColor = "cyan"
$AssessmentColor = "magenta"

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

## Check whether modern authentication is enabled for Exchange Online, and if not, enable it:
$OrgConfig = Get-OrganizationConfig 

if ($OrgConfig.OAuth2ClientProfileEnabled) {
 
  Write-Host 
  Write-Host -ForegroundColor $MessageColor "Modern Authentication für Exchange Online is bereits aktiviert,"
} 
else {
  Write-Host
  Write-Host -ForegroundColor $AssessmentColor "Modern Authentication für Exchange online is not aktiviert."
  Write-Host 
  
  $Answer = Read-Host "Do you want to enable Modern Authentication for Exchange Online now? Type Y or N and press Enter to continue"
  
  if ((Request-Choice -Caption 'Möchten Sie die Modern Authentication für Exchange Online jetzt aktivieren?') -eq 0) {
  
    Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Modern Authentication ist jetzt aktiviert."
    
  } 
  else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Modern Authentication wurde nicht aktiviert."
  }
}

## Create an authentication policy to block basic authentication
$PolicyName = 'Blockierung Basic Auth - M365Skript'
$CheckPolicy = Get-AuthenticationPolicy | Where-Object {$_.Name -contains $PolicyName}

if (!$CheckPolicy) {
  New-AuthenticationPolicy -Name $PolicyName
  Write-Host 
  Write-Host -ForegroundColor $MessageColor "Authentifizierungsrichtlinie zur Blockierung der Legacy Authentifizierung wurde erstellt."
} 
else {
  Write-Host 
  Write-Host -ForegroundColor $MessageColor "Die Authentifizierungsrichtlinie zur Blockierung der Legacy Authentifizierung existiert bereits"
}

## Prompt whether or not to make Block Basic Auth the default policy for the organization
Write-Host 

if ((Request-Choice -Caption ("Soll die Richtlinie [{0}] als Standard-Authentifizierungsrichtlinie konfiguriert werden?`nWARNUNG: Nach der Aktivierung können sich ältere Clients nicht mehr mit Exchange Online verbinden." -f $PolicyName)) -eq 0) {

  Set-OrganizationConfig -DefaultAuthenticationPolicy $PolicyName
  Write-Host 
  Write-Host -ForegroundColor $MessageColor ('Die Richtinie [{0}] wurde als Standard-Authentifizierungsrichtlinie des Mandanten aktiviert. Weitere Informationen zur Konfiguration von Ausnahmen finden Sie am Ende des PowerShell-Skriptes.' -f $PolicyName)
} 
else {
  Write-Host 
  Write-Host -ForegroundColor $AssessmentColor ("Die Richtinie [{0}] wurde nicht als Standard-Authentifizierungsrichtlinie des Mandanten aktiviert. Weisen Sie die Richtlinie jedem Anwender manuell zu: Set-User -Identity <username> -AuthenticationPolicy '{1}'" -f $PolicyName)
  Write-Host 
}

## OPTIONAL: Assign the 'Block Basic Auth' policy explicitly to all users
## Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"

## OPTIONAL: 
## Create additional authentication policies for allowing exceptions for basic authentication (e.g. for service accounts)

## EXAMPLE:
## New-AuthenticationPolicy "Allow Basic Auth Exception"

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
## Set-AuthenticationPolicy "Allow Basic Auth Exceptions"  -AllowBasicAuthImap

## To assign the exception policy to an account use:
## $ExceptionUser = username@domain.com
## Set-User -Identity $ExceptionUser -AuthenticationPolicy "Allow Basic Auth Exceptions"

## End of script