# Test Strategy

## Campaign levels

### Smoke fuzzing

Use in PR or pre-commit validation.

- Small number of cases
- No destructive target actions
- Dry-run or loopback target where possible
- Basic parser and schema validation

### Nightly fuzzing

Use in a controlled lab.

- Thousands of test cases
- PCAP capture enabled
- Service monitor enabled
- Crash and timeout triage enabled

### Release fuzzing

Use before release or major integration.

- Long-running stateful campaigns
- Route/tunnel stability monitoring
- Memory and file descriptor leak monitoring
- Regression replay for all previous bugs

## Result classification

```text
OK                       Expected behavior
TIMEOUT                  No response within timeout
CONNECTION_RESET         TCP reset or abrupt close
PROTOCOL_ERROR           Target returned protocol-level error
CRASH_SUSPECT            Monitor observed process restart or core file
STATE_CONFUSION          Invalid state transition appeared accepted
SECURITY_POLICY_BYPASS   Unexpected success for invalid authentication or crypto state
RESOURCE_LEAK            CPU, memory, FD, or queue growth after repeated cases
```

## Must-have evidence for every bug

- Exact packet bytes
- Protocol and layer
- Seed value
- Mutation name
- Test sequence order
- Timing
- PCAP if available
- Target version
- Monitor output before and after
- Minimal reproducer
