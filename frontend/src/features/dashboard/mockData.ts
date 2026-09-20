export const recentInvestigations = [
  { id: 'INV-1024', subject: 'Suspicious Invoice Payment Request', classification: 'BEC / Wire Fraud', risk: 'CRITICAL', score: 91, status: 'OPEN', date: '2026-09-19 10:42' },
  { id: 'INV-1023', subject: 'Microsoft 365 OAuth Token Phish', classification: 'Credential Harvester', risk: 'HIGH', score: 88, status: 'OPEN', date: '2026-09-18 14:15' },
  { id: 'INV-1022', subject: 'Payroll Direct Deposit Update', classification: 'Social Engineering', risk: 'HIGH', score: 78, status: 'UNDER REVIEW', date: '2026-09-18 09:30' },
  { id: 'INV-1021', subject: 'Critical Vulnerability Patch Action', classification: 'Domain Spoof', risk: 'MEDIUM', score: 74, status: 'CLOSED', date: '2026-09-17 16:45' },
  { id: 'INV-1020', subject: 'Okta MFA Device Verification', classification: 'Quishing / QR Phish', risk: 'MEDIUM', score: 58, status: 'OPEN', date: '2026-09-17 11:20' },
];

export const recentAlerts = [
  { id: 'ALT-892', type: 'Origin IP Mismatch', detail: 'Received-SPF failed for paypal-security.com', time: '10 mins ago', severity: 'High' },
  { id: 'ALT-891', type: 'Typosquatting Detected', detail: 'paypa1.com vs paypal.com (Score: 98%)', time: '45 mins ago', severity: 'Critical' },
  { id: 'ALT-890', type: 'New Infrastructure', detail: 'ASN 12345 (Cloud Pte) first seen', time: '2 hours ago', severity: 'Medium' },
];

export const threatDistribution = [
  { name: 'Business Email Compromise (BEC)', count: 685, percentage: 48, color: '#2563eb' },
  { name: 'Credential Harvester', count: 414, percentage: 29, color: '#d97706' },
  { name: 'Malware Attachments', count: 214, percentage: 15, color: '#dc2626' },
  { name: 'VIP Spoofing', count: 115, percentage: 8, color: '#64748b' },
];
