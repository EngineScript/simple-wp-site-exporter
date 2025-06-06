---
name: "Psalm Static Analysis Failure"
about: "Automated issue created when Psalm static analysis fails"
title: "Psalm Static Analysis Failed"
labels: ["bug", "psalm", "static-analysis"]
assignees: []
---

## Psalm Static Analysis Failed

The Psalm static analysis check has failed for the repository.

**Failure Details:**
- **PHP Version:** {{ env.PHP_VERSION }}
- **Workflow Run:** [View Details]({{ env.WORKFLOW_URL }})
- **Run ID:** {{ env.RUN_ID }}

**What happened:**
Psalm has detected potential issues in the code through static analysis.

**What needs to be done:**
1. Review the Psalm output in the failed workflow run
2. Address static analysis issues such as:
   - Type errors
   - Undefined variables or methods
   - Incorrect return types
   - Unused code
   - Potential null pointer issues
3. Test locally with: `./vendor/bin/psalm`

**Resources:**
- [Psalm Documentation](https://psalm.dev/)
- [Psalm Error Levels](https://psalm.dev/docs/running_psalm/error_levels/)

This issue was automatically created by the CI/CD pipeline.
