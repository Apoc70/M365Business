# PowerSkripte für Exchange Online

## Set-M365BusinessBaselineConfiguration.ps1

Dieses PowerShell-Skript dient der Basiskonfiguration von Exchange Online eines Microsoft 365 Business Premium Mandanten.

Für die Ausführung des ÜpwerShell-Skriptes ist das Exchange Online Management MOdul V2 erforderlich.

Stellen Sie sicher, dass Sie vor der Ausführung des Skriptes die Anpassung des Mandanten aktivieren. Nutzen Sie hierzu das folgende EXO V2-Cmdlet:

BUtEnable-OrganizationCustomization

Folgende Komponenten können konfiguriert werden:

- Aktivierung des Unified Audit Logs
- Aktivierung der Modern Authentication
- Blockierung der Legacy Authentication
- Deaktvierung automatischer Weiterleitungen an externe Empfänger
- Best Practices Konfiguration der Anti-Spam Einstellungen
- Best Practices Konfiguration der Anti-Malware Einstellungen
- Best Practices Konfiguration der Anti-Spam Einstellungen für ausgehende Nachrichten
- Best Practices Konfiguration der Advanced Threat Protection
- Best Practices Konfiguration von ATP-SafeLinks
- Best Practices Konfiguration von ATP-SafeAttachments
- Best Practices Konfiguration von ATP-AntiPhishing

## Block-BasicAuth.ps1

Dieses PowerShell-Skript erstellt eine Authentifizeirungsrichtlinie, um die Legacy Authentifizierung zu blockieren.
