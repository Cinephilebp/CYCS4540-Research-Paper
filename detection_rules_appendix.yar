/*
===============================================================================
LabHost PhaaS Detection Rules
Generated from FBI IC3 Dataset Analysis (42,000 domains)
===============================================================================

YARA Rules for Domain/URL Pattern Detection
*/

rule LabHost_Financial_Sector_Phishing {
    meta:
        description = "Detects LabHost phishing domains targeting financial institutions"
        author = "Borsha Podder"
        date = "2025-10-31"
        reference = "FBI IC3 FLASH-20250429-001"
        severity = "high"
        confidence = "high"
    
    strings:
        // Canadian financial brands
        $ca_fin1 = /interac[-.]/i nocase
        $ca_fin2 = /e-?transfer[-.]/i nocase
        $ca_fin3 = /(rbc|bmo|scotia|cibc|td)[-.]/i nocase
        $ca_fin4 = /desjardins[-.]/i nocase
        
        // International financial
        $intl_fin1 = /paypal[-.]/i nocase
        $intl_fin2 = /(chase|wellsfargo|bankofamerica)[-.]/i nocase
        $intl_fin3 = /(hsbc|barclays|santander)[-.]/i nocase
        
        // Action verbs commonly used
        $action1 = /(secure|verify|update|confirm)[-.]/i
        $action2 = /(login|account|billing|payment)/i
        $action3 = /(suspended|locked|alert|urgent)/i
        
        // Suspicious TLDs
        $tld1 = /\.(xyz|online|live|help|sbs|cfd|pw)$/i
        $tld2 = /\.(info|digital|app|me)$/i
        
        // Numeric patterns
        $num_pattern = /[0-9]{3,}/
    
    condition:
        (($ca_fin1 or $ca_fin2 or $ca_fin3 or $ca_fin4) or 
         ($intl_fin1 or $intl_fin2 or $intl_fin3)) and
        ($action1 or $action2 or $action3) and
        ($tld1 or $tld2 or $num_pattern)
}

rule LabHost_Postal_Service_Phishing {
    meta:
        description = "Detects LabHost phishing domains impersonating postal services"
        author = "Borsha Podder"
        date = "2025-10-31"
        severity = "high"
    
    strings:
        // Postal service names
        $postal1 = /(canada-?post|poste-?can)/i nocase
        $postal2 = /an-?post/i nocase
        $postal3 = /(usps|ups|fedex|dhl)/i nocase
        $postal4 = /(royal-?mail|australia-?post)/i nocase
        $postal5 = /purolator/i nocase
        
        // Delivery-related keywords
        $delivery1 = /(delivery|package|parcel|shipment)/i
        $delivery2 = /(customs|fee|payment|charge)/i
        $delivery3 = /(notice|alert|notification)/i
        $delivery4 = /(redelivery|missed|redirect)/i
        
        // Urgency indicators
        $urgent1 = /(urgent|immediate|expire|final)/i
        $urgent2 = /(action|required|confirm|claim)/i
        
        // Hyphenated structure
        $hyphen = /-/
    
    condition:
        ($postal1 or $postal2 or $postal3 or $postal4 or $postal5) and
        ($delivery1 or $delivery2 or $delivery3 or $delivery4) and
        ($urgent1 or $urgent2) and
        #hyphen >= 2
}

rule LabHost_Government_Impersonation {
    meta:
        description = "Detects LabHost domains impersonating government services"
        author = "Borsha Podder"
        date = "2025-10-31"
        severity = "critical"
        tags = "government, tax, immigration"
    
    strings:
        // Government indicators
        $gov1 = /gov[-.]/i nocase
        $gov2 = /government[-.]/i nocase
        
        // Service types
        $service1 = /(revenue|tax|irs|hmrc)/i
        $service2 = /(customs|immigration|dmv)/i
        $service3 = /(benefits|pension|social)/i
        
        // Action keywords
        $action1 = /(refund|payment|claim|verify)/i
        $action2 = /(update|confirm|review|check)/i
        
        // Numeric ID pattern (common in gov phishing)
        $id_pattern = /[0-9]{5,}/
        
        // Country-specific TLDs
        $country_tld = /\.(ca|uk|au|us)$/i
    
    condition:
        ($gov1 or $gov2 or any of ($service*)) and
        any of ($action*) and
        ($id_pattern or $country_tld)
}

rule LabHost_Tech_Brand_Impersonation {
    meta:
        description = "Detects LabHost phishing targeting major tech companies"
        author = "Borsha Podder"
        date = "2025-10-31"
        severity = "high"
    
    strings:
        // Tech brands
        $brand1 = /(microsoft|windows|office365)/i nocase
        $brand2 = /(apple|icloud|itunes)/i nocase
        $brand3 = /(google|gmail|drive)/i nocase
        $brand4 = /(amazon|aws|prime)/i nocase
        $brand5 = /(netflix|spotify|adobe)/i nocase
        $brand6 = /(facebook|meta|instagram)/i nocase
        
        // Account-related terms
        $account1 = /(account|billing|subscription)/i
        $account2 = /(verify|confirm|update|secure)/i
        $account3 = /(suspended|locked|expired|alert)/i
        
        // Recovery/security terms
        $security1 = /(security|recovery|restore)/i
        $security2 = /(2fa|verification|authentication)/i
    
    condition:
        any of ($brand*) and
        (any of ($account*) or any of ($security*))
}

rule LabHost_Telecom_Provider_Phishing {
    meta:
        description = "Detects LabHost phishing targeting telecommunications providers"
        author = "Borsha Podder"
        date = "2025-10-31"
    
    strings:
        // Canadian providers
        $ca_tel1 = /(telus|rogers|bell)[-.]/i nocase
        $ca_tel2 = /(fido|koodo|virgin)[-.]/i nocase
        
        // US providers
        $us_tel1 = /(verizon|att|at&t)[-.]/i nocase
        $us_tel2 = /(tmobile|t-mobile|sprint)[-.]/i nocase
        
        // Service keywords
        $service1 = /(wireless|mobile|cellular)/i
        $service2 = /(bill|payment|invoice|account)/i
        $service3 = /(offer|promotion|upgrade|plan)/i
        
        // Action terms
        $action = /(update|verify|confirm|pay)/i
    
    condition:
        (any of ($ca_tel*) or any of ($us_tel*)) and
        any of ($service*) and
        $action
}

rule LabHost_Generic_Phishing_Structure {
    meta:
        description = "Detects generic phishing domain structures used by LabHost"
        author = "Borsha Podder"
        date = "2025-10-31"
        confidence = "medium"
    
    strings:
        // Common prefixes
        $prefix1 = /^secure[-.]/i
        $prefix2 = /^verify[-.]/i
        $prefix3 = /^update[-.]/i
        $prefix4 = /^account[-.]/i
        $prefix5 = /^login[-.]/i
        
        // Multiple hyphens (suspicious)
        $multi_hyphen = /[a-z]+-[a-z]+-[a-z]+/i
        
        // Random numbers
        $random_num = /[a-z]+[0-9]{3,}/i
        
        // Suspicious suffixes
        $suffix1 = /[-.](portal|login|secure|verify)$/i
        $suffix2 = /[-.](update|confirm|check|validate)$/i
    
    condition:
        (any of ($prefix*) or $multi_hyphen) and
        ($random_num or any of ($suffix*))
}

/*
===============================================================================
Sigma Rules for SIEM Integration
===============================================================================
*/

---
title: LabHost Financial Phishing DNS Query
id: 8f3e4a12-9c5d-4b6e-a1f3-2e8c9d5b7a4f
status: production
description: Detects DNS queries to suspected LabHost financial phishing domains
author: Borsha Podder
date: 2025-10-31
references:
    - https://www.ic3.gov/CSA/2025/250429.pdf
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.credential_access
    - attack.t1598
logsource:
    product: dns
    service: dns-query
detection:
    selection_financial_brands:
        query|contains:
            - 'interac-'
            - 'e-transfer-'
            - 'paypal-'
            - 'rbc-'
            - 'bmo-'
            - 'chase-'
            - 'wellsfargo-'
        query|endswith:
            - '.com'
            - '.info'
            - '.online'
            - '.xyz'
            - '.live'
    selection_suspicious_pattern:
        query|re: '(secure|verify|update|account)-.*(login|confirm|portal)'
    timeframe: 5m
    condition: selection_financial_brands or selection_suspicious_pattern
falsepositives:
    - Legitimate financial institution subdomains
    - CDN or cloud service endpoints
level: high
---
title: LabHost Delivery Service Phishing Pattern
id: 7d2f5e8a-4b9c-11ee-9a3d-1e8f4c9b2d7a
status: production
description: Detects patterns consistent with LabHost postal service phishing
author: Borsha Podder
date: 2025-10-31
logsource:
    product: proxy
    category: webproxy
detection:
    selection_postal_domains:
        c-uri|contains:
            - 'canada-post'
            - 'canadapost'
            - 'anpost'
            - 'royal-mail'
            - 'usps-'
            - 'fedex-'
            - 'dhl-'
            - 'ups-'
        c-uri|contains:
            - 'delivery'
            - 'package'
            - 'customs'
            - 'fee'
            - 'redelivery'
    selection_http_method:
        cs-method: 
            - 'POST'
            - 'GET'
    selection_suspicious_referer:
        cs-referer|contains:
            - 'bit.ly'
            - 'tinyurl'
            - 'ow.ly'
            - 't.co'
    condition: selection_postal_domains and selection_http_method and selection_suspicious_referer
falsepositives:
    - Legitimate shipping notifications
    - Marketing emails from postal services
level: high
---
title: LabHost Government Impersonation Detection
id: 3f8a9c2e-7d5b-4e1c-9f2a-8b4d6c3e5a7f
status: production
description: Detects access attempts to government impersonation domains
author: Borsha Podder
date: 2025-10-31
logsource:
    product: firewall
    service: network
detection:
    selection_gov_pattern:
        destination.domain|contains:
            - 'gov-'
            - 'revenue-'
            - 'tax-'
            - 'customs-'
            - 'immigration-'
        destination.domain|re: '.*[0-9]{5,}.*'
    selection_ports:
        destination.port:
            - 80
            - 443
    selection_suspicious_tld:
        destination.domain|endswith:
            - '.xyz'
            - '.online'
            - '.help'
            - '.live'
            - '.pw'
    condition: selection_gov_pattern and selection_ports and selection_suspicious_tld
falsepositives:
    - None expected for government domains with suspicious TLDs
level: critical
---
title: LabHost Multi-Brand Phishing Campaign
id: 9e7f3a5b-2c8d-4e6f-a3b5-1d9f8c7e2a5b
status: experimental
description: Detects multiple brand impersonation attempts indicating LabHost campaign
author: Borsha Podder
date: 2025-10-31
logsource:
    product: endpoint
    service: dns
detection:
    selection_multiple_brands:
        - query|contains: 'microsoft-'
        - query|contains: 'apple-'
        - query|contains: 'google-'
        - query|contains: 'amazon-'
        - query|contains: 'paypal-'
        - query|contains: 'netflix-'
    timeframe: 1h
    condition: 3 of selection_multiple_brands
falsepositives:
    - Security testing
    - Threat hunting activities
level: high
---
title: LabHost Credential Harvesting Endpoint Access
id: 5a8c9f3e-4d7b-11ee-8f3a-2e9c7d5b8a4f
status: production
description: Detects POST requests to suspected LabHost credential harvesting endpoints
author: Borsha Podder
date: 2025-10-31
logsource:
    product: webserver
    category: access
detection:
    selection_method:
        cs-method: 'POST'
    selection_path:
        cs-uri-path|contains:
            - '/login.php'
            - '/verify.php'
            - '/update.php'
            - '/confirm.php'
            - '/secure.php'
            - '/account.php'
    selection_suspicious_params:
        cs-uri-query|contains:
            - 'email='
            - 'password='
            - 'pin='
            - 'ssn='
            - 'card='
    selection_user_agent:
        cs-user-agent|contains:
            - 'Mozilla/5.0'
    condition: all of selection_*
falsepositives:
    - Legitimate login forms (verify domain reputation)
level: high

/*
===============================================================================
DNS Sinkhole/Blocklist Patterns
===============================================================================
*/

# LabHost Domain Blocklist Patterns
# Format: Regular expressions for DNS filtering

# Financial sector patterns
^(secure|verify|update|account)-.*(interac|paypal|rbc|bmo|chase).*\.(com|info|online|xyz)$
^(claim|confirm|suspended)-.*(transfer|deposit|payment).*\.(com|live|pw)$

# Postal/delivery patterns  
^(post|delivery|customs|package)-.*(canada|anpost|usps|fedex).*\.(com|ca|info|online)$
^(redelivery|missed|notice)-.*(fee|payment|charge).*\.(com|digital|help)$

# Government patterns
^gov-.*[0-9]{3,}.*\.(ca|com|xyz)$
^(revenue|tax|customs|immigration)-.*\.(info|online|help)$

# Tech brand patterns
^(microsoft|apple|google|amazon|netflix)-.*(account|verify|secure|update).*$
^(facebook|meta|instagram)-.*(security|locked|suspended).*$

# Telecom patterns
^(telus|rogers|bell|verizon|att)-.*(bill|payment|account|offer).*$

# Generic suspicious patterns
.*-[0-9]{4,}\.(xyz|online|live|help|sbs|cfd|pw|digital|app|me)$
^(secure|verify|update|login|account)-.*-.*\.(com|info|online)$

/*
===============================================================================
IDS/IPS Snort Rules
===============================================================================
*/

# LabHost phishing domain detection
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LabHost Phishing Domain Access - Financial"; flow:to_server,established; content:"Host|3a 20|"; content:"interac-"; nocase; http_header; pcre:"/Host\x3a\x20[^\r\n]*(secure|verify|update)-[^\r\n]*(interac|paypal|rbc|bmo)/i"; classtype:trojan-activity; sid:1000001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LabHost Phishing Domain Access - Postal"; flow:to_server,established; content:"Host|3a 20|"; content:"post"; nocase; http_header; pcre:"/Host\x3a\x20[^\r\n]*(canada-?post|an-?post|usps)[^\r\n]*(delivery|customs|fee)/i"; classtype:trojan-activity; sid:1000002; rev:1;)

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LabHost Credential Theft Form"; flow:from_server,established; content:"<form"; nocase; content:"password"; distance:0; within:500; content:"submit"; distance:0; within:200; pcre:"/<form[^>]*action=['\"][^'\"]*\/(login|verify|update|secure)\.php/i"; classtype:trojan-activity; sid:1000003; rev:1;)

# Email-based LabHost phishing detection
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LabHost Phishing Email - Delivery Lure"; flow:to_server,established; content:"Subject|3a|"; content:"delivery"; nocase; content:"fee"; nocase; distance:0; within:100; pcre:"/Subject\x3a[^\r\n]*(package|parcel|customs)[^\r\n]*(fee|payment|charge)/i"; classtype:trojan-activity; sid:1000004; rev:1;)

/*
===============================================================================
Notes for Implementation
===============================================================================

1. YARA Rules:
   - Deploy on email gateways and web proxies
   - Integrate with EDR solutions for URL scanning
   - Use in threat hunting operations

2. Sigma Rules:
   - Convert to specific SIEM syntax (Splunk, QRadar, Sentinel)
   - Adjust field names based on log source
   - Tune thresholds based on environment

3. DNS Blocklist:
   - Import into DNS filtering solutions (BIND RPZ, Infoblox, etc.)
   - Update regularly based on new indicators
   - Monitor for false positives

4. IDS/IPS Rules:
   - Test in detection-only mode first
   - Adjust HOME_NET and EXTERNAL_NET variables
   - Monitor performance impact

5. Recommended Actions:
   - Alert: High-confidence patterns
   - Block: Known malicious domains from FBI list
   - Quarantine: Suspicious emails matching patterns
   - Log: All matches for threat hunting

===============================================================================
*/
