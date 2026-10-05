export const DEMO_PRESETS = [
  {
    id: "legit",
    title: "1. Legitimate Business Email",
    threat: "LOW (Score: 5/100)",
    badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    description: "Valid SPF/DKIM/DMARC, corporate sender domain, clean roadmaps & notes.",
    raw: `Received: from mail-ej1-f42.google.com (mail-ej1-f42.google.com [209.85.218.42])
    by mx.cybercell.gov.in with ESMTPS id 8192abc
    for <investigations@cybercell.gov.in>; Mon, 05 Oct 2026 10:15:00 +0000
From: Sarah Jenkins <sjenkins@acmecorp.com>
To: investigations@cybercell.gov.in
Subject: [DEMO DATA] Q4 Product Strategy & Security Roadmap Sync
Date: Mon, 05 Oct 2026 10:15:00 +0000
Message-ID: <20261005101500.8192A@acmecorp.com>
Authentication-Results: mx.cybercell.gov.in; spf=pass; dkim=pass; dmarc=pass

Hi Team,

Attached is the finalized Q4 product strategy and security roadmap for your review.
Please review Section 3 regarding API security hardening prior to our Thursday sync.

Best regards,
Sarah Jenkins
Director of Product, Acme Corp
`
  },
  {
    id: "phishing",
    title: "2. Credential Phishing (Microsoft 365)",
    threat: "CRITICAL (Score: 94/100)",
    badgeColor: "bg-red-500/10 text-red-400 border-red-500/30",
    description: "Spoofed Microsoft 365 notice, Tor exit node origin (185.220.101.5), credential request link.",
    raw: `Received: from vps-nl-node12.untrusted-host.net (185.220.101.5)
    by mx.acmecorp.com with SMTP id 9921xyz
    for <user.admin@acmecorp.com>; Mon, 05 Oct 2026 14:20:00 +0000
From: Microsoft Security Team <no-reply@account-verify-sec365-update.com>
Reply-To: support@account-verify-sec365-update.com
To: user.admin@acmecorp.com
Subject: [DEMO DATA] URGENT: Microsoft 365 Password Expiration Notice
Date: Mon, 05 Oct 2026 14:20:00 +0000
Authentication-Results: mx.acmecorp.com; spf=fail; dkim=fail; dmarc=fail

Your Microsoft 365 password expires in 2 hours.
To retain access to your corporate emails and SharePoint files, you must immediately re-authenticate at:
https://account-verify-sec365-update.com/login/auth-ref-9821

Failure to verify will result in immediate mailbox suspension.
`
  },
  {
    id: "bec",
    title: "3. CEO Impersonation (BEC)",
    threat: "CRITICAL (Score: 91/100)",
    badgeColor: "bg-red-500/10 text-red-400 border-red-500/30",
    description: "David Miller CEO display-name impersonation, Reply-To mismatch, urgent $145,000 wire transfer.",
    raw: `Received: from host-45-142-214-120.bulletproof-vps.com (45.142.214.120)
    by mx.acmecorp.com with ESMTP id 7781bec
    for <finance@acmecorp.com>; Mon, 05 Oct 2026 17:10:00 +0000
From: David Miller (CEO) <ceo.david.miller@executive-mail-portal.org>
Reply-To: david.miller.private101@gmail.com
To: finance@acmecorp.com
Subject: [DEMO DATA] CONFIDENTIAL: Urgent Wire Transfer Required for Project Alpha Acquisition
Date: Mon, 05 Oct 2026 17:10:00 +0000
Authentication-Results: mx.acmecorp.com; spf=softfail; dmarc=fail

Hi Finance Team,

I am currently in closed-door M&A negotiations for Project Alpha.
I need an urgent wire transfer of $145,000 processed immediately to secure the acquisition deposit.

Do NOT call me or discuss this with anyone as this is under strict SEC NDA.
Reply directly to this email for wire instructions.

David Miller
Chief Executive Officer, Acme Corp
`
  },
  {
    id: "invoice",
    title: "4. Fake Invoice / Payment Diversion",
    threat: "HIGH (Score: 86/100)",
    badgeColor: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    description: "Vendor billing scam, domain registered 2 days ago, offshore wire transfer diversion instructions.",
    raw: `Received: from mail.vendor-supplies-global.co.uk (194.26.29.110)
    by mx.acmecorp.com with ESMTP id 4412inv
    for <ap-dept@acmecorp.com>; Mon, 05 Oct 2026 12:40:00 +0000
From: Global Vendor Billing <billing@vendor-supplies-global.co.uk>
Reply-To: payments@vendor-supplies-global.co.uk
To: ap-dept@acmecorp.com
Subject: [DEMO DATA] Overdue Invoice #INV-2026-8819 - Updated Offshore Settlement Instructions
Date: Mon, 05 Oct 2026 12:40:00 +0000

Dear Accounts Payable,

Please find attached overdue Invoice #INV-2026-8819 for $68,400.
Note: Our UK banking partner is currently undergoing audit maintenance.
Please process this payment to our updated offshore account details specified in the attached PDF.

Thank you,
Global Vendor Supplies Ltd
`
  },
  {
    id: "malware-link",
    title: "5. Malicious Link Email",
    threat: "CRITICAL (Score: 96/100)",
    badgeColor: "bg-red-500/10 text-red-400 border-red-500/30",
    description: "Typosquatted HR domain (login-acmecorp-hr.com), unencrypted HTTP link, blacklisted IP origin.",
    raw: `Received: from relay.badactor-net.com (103.251.167.20)
    by mx.acmecorp.com with ESMTP id 1120mal
    for <all-employees@acmecorp.com>; Mon, 05 Oct 2026 19:10:00 +0000
From: HR Benefits Operations <hr-notice@internal-benefits-acme-update.net>
To: all-employees@acmecorp.com
Subject: [DEMO DATA] Security Action Required: Employee Benefits Portal Upgrade
Date: Mon, 05 Oct 2026 19:10:00 +0000

Dear Employees,

Our annual benefits open-enrollment portal has been upgraded.
To confirm your 2026 healthcare elections and prevent coverage lapse, log in here:
http://login-acmecorp-hr.com/update/credential-harvest

HR Operations Team
`
  }
];

export const DEMO_RAW_EMAIL = DEMO_PRESETS[1].raw;
