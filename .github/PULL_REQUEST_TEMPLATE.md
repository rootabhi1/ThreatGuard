<!-- Thanks for contributing! Keep PRs small and focused. -->

## Summary

<!-- What does this change and why? -->

## Related issue

<!-- e.g. Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Refactor / chore
- [ ] CI / build

## How was this tested?

<!-- Commands run, scenarios covered. -->

```bash
cd threat-modeler
export JWT_SECRET=test INITIAL_ADMIN_EMAIL=admin@corp.io \
       INITIAL_ADMIN_PASSWORD='AdminPass123!' RATE_LIMIT_ENABLED=0
for t in tests/test_*.py; do python3 "$t"; done
ruff check .
```

## Checklist

- [ ] All 8 test suites pass and `ruff check .` is clean
- [ ] No secrets committed; new env vars added to `.env.example`
- [ ] Documentation updated if behavior changed
- [ ] Change is small and focused (one concern)
- [ ] For new endpoints: auth/permissions enforced and covered by tests
