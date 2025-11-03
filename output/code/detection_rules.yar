/*
LabHost Phishing Domain Detection Rules
Generated from analysis of 50 sampled domains
Date: 2025-11-03
*/

rule LabHost_Financial_Phishing {
    meta:
        description = "Detects LabHost phishing domains targeting financial institutions"
        author = "Borsha Podder"
        date = "2025-11-03"
        reference = "FBI IC3 LabHost Dataset Analysis"
    
    strings:
        $brand1 = /interac[-.]/i
        $brand2 = /paypal[-.]/i
        $brand3 = /(rbc|bmo|scotia|cibc|chase|wellsfargo)[-.]/i
        $suspicious = /(secure|verify|update|login|account|suspended)/i
        $tld = /\.(com|info|online|xyz|ca|live)$/i
    
    condition:
        ($brand1 or $brand2 or $brand3) and $suspicious and $tld
}

rule LabHost_Delivery_Phishing {
    meta:
        description = "Detects LabHost phishing domains impersonating delivery services"
        author = "Borsha Podder"
        date = "2025-11-03"
    
    strings:
        $delivery = /(canada-?post|an-?post|usps|fedex|dhl|ups)/i
        $lure = /(customs|fee|payment|package|parcel|delivery|notice)/i
        $action = /(claim|verify|update|confirm|track)/i
        $hyphen = /-/
    
    condition:
        $delivery and $lure and $action and #hyphen >= 2
}

rule LabHost_Government_Impersonation {
    meta:
        description = "Detects LabHost domains impersonating government services"
        author = "Borsha Podder"
        date = "2025-11-03"
    
    strings:
        $gov = /gov[-.]/i
        $service = /(revenue|tax|customs|immigration|dmv)/i
        $numeric = /\d{3,}/
        $action = /(refund|payment|verify|claim|update)/i
    
    condition:
        ($gov or $service) and $numeric and $action
}

rule LabHost_Tech_Brand_Phishing {
    meta:
        description = "Detects LabHost phishing targeting tech companies"
        author = "Borsha Podder"
        date = "2025-11-03"
    
    strings:
        $brand = /(microsoft|apple|google|amazon|netflix|adobe)/i
        $account = /(account|billing|payment|subscription|verify)/i
        $urgent = /(urgent|suspended|locked|expire|alert)/i
        $structure = /-/
    
    condition:
        $brand and $account and ($urgent or #structure >= 2)
}

rule LabHost_Generic_Suspicious_Structure {
    meta:
        description = "Detects generic suspicious domain structures used by LabHost"
        author = "Borsha Podder"
        date = "2025-11-03"
    
    strings:
        $prefix = /^(secure|verify|update|login|account|payment)/i
        $hyphen = /-/
        $suffix = /(portal|login|verify|confirm|update)$/i
        $numbers = /\d{3,}/
    
    condition:
        $prefix and #hyphen >= 2 and ($suffix or $numbers)
}


# ============================================================
# Sigma Rules for SIEM Integration
# ============================================================

title: LabHost Phishing Domain Detection
id: a176281d80b680672bc05f66f67aba5d
status: experimental
description: Detects DNS queries to suspected LabHost phishing domains
author: Borsha Podder
date: 2025/11/03
references:
    - https://www.ic3.gov/CSA/2025/250429.pdf
    - FBI IC3 LabHost Domain Analysis
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1566.002
logsource:
    product: dns
    service: dns
detection:
    selection_financial:
        query|contains:
            - 'interac-'
            - 'paypal-'
            - 'rbc-'
            - 'bmo-'
            - 'chase-'
        query|endswith:
            - '.com'
            - '.info'
            - '.online'
            - '.xyz'
    selection_delivery:
        query|contains:
            - 'canada-post'
            - 'canadapost'
            - 'anpost'
            - 'usps-'
            - 'fedex-'
            - 'dhl-'
        query|contains:
            - 'customs'
            - 'fee'
            - 'package'
            - 'delivery'
    selection_gov:
        query|contains:
            - 'gov-'
            - 'revenue-'
            - 'tax-'
            - 'customs-'
        query|re: '.*\d{3,}.*'
    selection_tech:
        query|contains:
            - 'microsoft-'
            - 'apple-'
            - 'google-'
            - 'amazon-'
            - 'netflix-'
        query|contains:
            - 'account'
            - 'verify'
            - 'suspended'
            - 'locked'
    suspicious_structure:
        query|re: '^(secure|verify|update|login)-.+-.+(com|info|online)$'
    condition: selection_financial or selection_delivery or selection_gov or selection_tech or suspicious_structure
falsepositives:
    - Legitimate subdomains that match the pattern
    - CDN or cloud service subdomains
level: high

---

title: LabHost Phishing HTTP Request Pattern
id: de181d2623d3db975a9b866fc84f9c90
status: experimental
description: Detects HTTP requests to LabHost phishing infrastructure
author: Borsha Podder
date: 2025/11/03
logsource:
    product: proxy
    category: webproxy
detection:
    selection_domains:
        c-dns|contains:
            - 'secure-'
            - 'verify-'
            - 'update-'
            - 'account-'
        c-dns|endswith:
            - '.xyz'
            - '.online'
            - '.live'
            - '.sbs'
            - '.help'
    selection_path:
        cs-uri-path|contains:
            - '/login'
            - '/verify'
            - '/account'
            - '/billing'
            - '/secure'
    selection_referer:
        cs-referer|contains:
            - 'bit.ly'
            - 'tinyurl'
            - 't.co'
            - 'goo.gl'
    condition: selection_domains and (selection_path or selection_referer)
falsepositives:
    - Legitimate services with similar naming patterns
level: medium
