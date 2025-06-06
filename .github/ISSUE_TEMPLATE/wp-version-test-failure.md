---
name: "WordPress Version Compatibility Test Failure"
about: "Automated issue created when WordPress version compatibility tests fail"
title: "WordPress Version Compatibility Test Failed"
labels: ["bug", "compatibility", "wordpress-version"]
assignees: []
---

## WordPress Version Compatibility Test Failed

The WordPress version compatibility test has failed.

**Failure Details:**
- **PHP Version:** {{ env.PHP_VERSION }}
- **WordPress Version:** {{ env.WP_VERSION }}
- **Workflow Run:** [View Details]({{ env.WORKFLOW_URL }})
- **Run ID:** {{ env.RUN_ID }}

**What happened:**
The plugin failed to work correctly with WordPress {{ env.WP_VERSION }} on PHP {{ env.PHP_VERSION }}.

**What needs to be done:**
1. Review the test output in the failed workflow run
2. Identify compatibility issues with WordPress {{ env.WP_VERSION }}
3. Fix any deprecated function calls or API usage
4. Ensure plugin works correctly with this WordPress version
5. Update plugin compatibility metadata if needed
6. Test locally with WordPress {{ env.WP_VERSION }}

**Potential Issues:**
- Deprecated WordPress functions
- Changed WordPress APIs
- PHP version incompatibilities with this WordPress version
- Plugin initialization problems

**Resources:**
- [WordPress Backward Compatibility](https://developer.wordpress.org/plugins/plugin-basics/determining-plugin-and-content-directories/)
- [WordPress Deprecated Functions](https://developer.wordpress.org/reference/functions/)

This issue was automatically created by the CI/CD pipeline.
