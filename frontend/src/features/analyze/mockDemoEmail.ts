export const DEMO_RAW_EMAIL = `Received: from mail-qv1-f65.google.com (mail-qv1-f65.google.com [209.85.219.65])
    by mx.secureserver.net (8.14.7/8.14.7) with ESMTP id 39DFH2k9014523
    for <security@enterprise-corp.com>; Thu, 18 Sep 2026 14:22:10 -0400
ARC-Seal: i=1; a=rsa-sha256; t=1726683730; cv=none; d=google.com; s=arc-20240605;
    b=kL92jXz98mP1O8QvX7yN3uB2m1k0j9i8h7g6f5e4d3c2b1a0...
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
    h=to:subject:message-id:date:from:mime-version:dkim-signature;
    bh=X9yZ8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8cC7bA6m4=;
    b=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789...
ARC-Authentication-Results: i=1; mx.google.com;
    dkim=pass header.i=@secure-update-verify.com header.s=s1 header.b=X9aB8cD7;
    spf=pass (google.com: domain of support@secure-update-verify.com designates 209.85.219.65 as permitted sender) smtp.mailfrom=support@secure-update-verify.com;
    dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=executive-payroll.com
Return-Path: <support@secure-update-verify.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=secure-update-verify.com; s=s1;
    h=from:to:subject:date:message-id:mime-version:content-type;
    bh=X9yZ8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8cC7bA6m4=;
    b=X9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT9uV8wX7yZ6aB5cD4eF3gH2iJ1kL0mN9oP
From: "Corporate HR & Payroll Dept" <hr-payroll@executive-payroll.com>
To: <security@enterprise-corp.com>
Subject: URGENT: Action Required - Direct Deposit Authentication Audit #8942
Date: Thu, 18 Sep 2026 18:22:04 +0000
Message-ID: <20260918182204.89421A4F8@mail-relay-04.secure-update-verify.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_NextPart_000_01DB_8942A10"
X-Mailer: Microsoft Outlook 16.0
X-Originating-IP: [194.165.16.42]

------=_NextPart_000_01DB_8942A10
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Team Member,

During our quarterly security audit, we detected a discrepancy in your direct deposit account configuration. 

To prevent interruption to your upcoming payroll distribution, you must verify your identity immediately:

https://verify-payroll-portal.auth-portal-secure.net/login?token=e98f01a3-4b2c-4d8e

Failure to complete verification within 24 hours will defer payroll disbursement to the next pay cycle.

Regards,
Human Resources & Payroll Compliance Team
------=_NextPart_000_01DB_8942A10--
`;
