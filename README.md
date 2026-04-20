# Cloud-Platform-AntiDDoS

Update on 20th April 2026:
- In WAF_POP: CDN Implemented but not implemented in WAF
- In WAF_POP: WAF now have implemented rate limit againts ddos flooding attacks
- In WAF_POP: WAF detect bot requests via User_agent header


Update on 18th April 2026:
- POP implemented using load balance
- WAF specialized in SQL Injection
- All are incorporated in a Docker image (scalable number of WAFs)

Acest reposiotry constituie lucrarea mea de licenta.

Referinte:
*CloudFlare docs

Pentru DNS Resolver si Name Service
*RFC 1034
*RFC 1035

Pentru WAF:
*RFC 3986
*RFC 9110
*https://owasp.org/Top10/2025/A05_2025-Injection/
*OWASP ModSecurity Core Rule Set (CRS)
*SQL Injection Knowledgebase (via @LightOS) -> http://websec.ca/kb/sql_injection
*SQLi Filter Evasion Cheat Sheet -> http://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql

Pentru CDN:
*RFC 9110
*RFC 5861
