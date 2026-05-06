OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/01_broken_access_control.tf:42 azurerm_storage_account.anon_blob
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/01_broken_access_control.tf:42 azurerm_storage_account.anon_blob
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/01_broken_access_control.tf:42 azurerm_storage_account.anon_blob
SEC-AZURE-RBAC-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/01_broken_access_control.tf:35 azurerm_role_assignment.subscription_contributor
SEC-AZURE-STORAGE-002 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/01_broken_access_control.tf:42 azurerm_storage_account.anon_blob
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/07_identification_auth.tf:33 azurerm_storage_account.for_app
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/07_identification_auth.tf:73 azurerm_mssql_server.sql_only
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/07_identification_auth.tf:33 azurerm_storage_account.for_app
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/07_identification_auth.tf:33 azurerm_storage_account.for_app
SEC-AZURE-WEBAPP-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/07_identification_auth.tf:51 azurerm_linux_web_app.key_based
SEC-SECRETS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/07_identification_auth.tf:79 
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:81 azurerm_storage_account.open_storage
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:61 azurerm_kubernetes_cluster.no_rbac
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:81 azurerm_storage_account.open_storage
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:81 azurerm_storage_account.open_storage
SEC-AZURE-AKS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:61 azurerm_kubernetes_cluster.no_rbac
SEC-AZURE-AKS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:61 azurerm_kubernetes_cluster.no_rbac
STK-AZURE-NSG-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:7 
STK-AZURE-NSG-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:42 
STK-AZURE-NSG-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/05_security_misconfiguration.tf:54 
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/10_ssrf.tf:62 azurerm_storage_account.ssrf_target
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/10_ssrf.tf:62 azurerm_storage_account.ssrf_target
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/10_ssrf.tf:62 azurerm_storage_account.ssrf_target
SEC-AZURE-WEBAPP-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/10_ssrf.tf:46 azurerm_linux_web_app.publicly_reachable
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/versions.tf:26 azurerm_resource_group.demo
ROB-VERSION-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/versions.tf:9 
MOD-PIN-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/06_vulnerable_components.tf:86 module.unpinned_aks
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/06_vulnerable_components.tf:38 azurerm_storage_account.fnapp
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/06_vulnerable_components.tf:67 azurerm_kubernetes_cluster.old_k8s
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/06_vulnerable_components.tf:38 azurerm_storage_account.fnapp
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/06_vulnerable_components.tf:38 azurerm_storage_account.fnapp
SEC-AZURE-AKS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/06_vulnerable_components.tf:67 azurerm_kubernetes_cluster.old_k8s
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/09_logging_monitoring.tf:34 azurerm_key_vault.unaudited
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:35 azurerm_storage_account.weak_tls
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:35 azurerm_storage_account.weak_tls
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:48 azurerm_key_vault.no_purge_protection
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:35 azurerm_storage_account.weak_tls
SEC-AZURE-KV-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:48 azurerm_key_vault.no_purge_protection
SEC-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:35 azurerm_storage_account.weak_tls
SEC-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/02_cryptographic_failures.tf:35 azurerm_storage_account.weak_tls
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/08_data_integrity.tf:30 azurerm_storage_account.no_soft_delete
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/08_data_integrity.tf:45 azurerm_mssql_database.no_retention
ROB-AZURE-LIFECYCLE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/08_data_integrity.tf:30 azurerm_storage_account.no_soft_delete
ROB-AZURE-SQL-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/08_data_integrity.tf:45 azurerm_mssql_database.no_retention
ROB-AZURE-STORAGE-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/08_data_integrity.tf:30 azurerm_storage_account.no_soft_delete
OPS-AZURE-TAGS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/04_insecure_design.tf:46 azurerm_mssql_server.stateful
SEC-SECRETS-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/04_insecure_design.tf:35 
SEC-PROVISIONER-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/03_injection.tf:65 
CI-TEST-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/01_broken_access_control.tf:1 <module:azure>
SEC-AZURE-LOGGING-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure:0 <absent: azurerm_monitor_diagnostic_setting>
SEC-AZURE-MI-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure/04_insecure_design.tf:39 azurerm_user_assigned_identity.monolith
SEC-AZURE-SQL-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure:0 <absent: azurerm_mssql_server_azure_ad_administrator>
STK-AZURE-NSG-FLOWLOG-001 /Users/chris.adkin/Projects/tf-analyze/examples/terragoat/azure:0 <absent: azurerm_network_watcher_flow_log>
