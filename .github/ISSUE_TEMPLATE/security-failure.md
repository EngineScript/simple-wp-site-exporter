---
name: "Security Vulnerability Detected"
about: "Automated issue created when security vulnerabilities are detected"
title: "Security Vulnerability Detected"
labels: ["security", "vulnerability", "critical"]
assignees: []
---

## Security Vulnerability Detected

A security vulnerability has been detected in the project dependencies.

**Failure Details:**
- **PHP Version:** {{ env.PHP_VERSION }}
- **Workflow Run:** [View Details]({{ env.WORKFLOW_URL }})
- **Run ID:** {{ env.RUN_ID }}

**What happened:**
The security checker has identified known vulnerabilities in one or more of the project's dependencies.

**What needs to be done:**
1. Review the security check output in the failed workflow run
2. Identify which dependencies have vulnerabilities
3. Update vulnerable dependencies to secure versions
4. If updates are not available, consider:
   - Finding alternative packages
   - Applying patches if available
   - Implementing workarounds
5. Test the application after updates

**⚠️ Priority:** This is a security issue and should be addressed immediately.

**Resources:**
- [Symfony Security Checker](https://github.com/FriendsOfPHP/security-advisories)
- [WordPress Security Best Practices](https://developer.wordpress.org/plugins/security/)

This issue was automatically created by the CI/CD pipeline.
