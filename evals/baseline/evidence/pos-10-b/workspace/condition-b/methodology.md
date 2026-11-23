# Cross-user authorization assessment guidance

Treat an HTTP success as an observation, not as a policy verdict. First confirm that the available account sessions resolve to distinct stable subjects. For each declared resource class, begin from a valid owner baseline: create a new object while signed in as an allowed owner, put a fresh unpredictable marker in every owner-controlled field, and confirm that the owner can retrieve the same object and marker.

Exercise the declared read and write policies consistently across the full resource list. Compare an attempted access by another available subject with the owner baseline and with the relevant negative or permitted-audience control. Where anonymous, authenticated, tenant, or explicitly shared access is allowed, a matching response is not a violation. Check declared sharing state before interpreting another subject's access.

Correlate the result to the object created in this run. A status code alone is insufficient: login pages, stale values, shared data, public data, error bodies, caches, echoed markers, and a second session for the same subject can all resemble cross-user access. Use the response body or independently observed target state to establish what was read or changed. Recheck identity after a request that might revoke or rotate a session.

Report a finding only when the measured actor, object, operation, and effect contradict the declared rule. Preserve the request and response evidence, the fresh marker, identity probes, baseline, control, and any incomplete-body or state qualifications. If the evidence remains ambiguous, describe the exercised scope and abstain from the positive claim.
