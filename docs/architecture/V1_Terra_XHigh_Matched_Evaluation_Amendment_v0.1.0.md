# V1 Terra XHigh Matched Evaluation Amendment

```text
DOCUMENT_ID = PI-GACW-V1-TERRA-XHIGH-MATCHED-EVALUATION-AMENDMENT
DOCUMENT_VERSION = 0.1.0
STATUS = PROSPECTIVE_NARROW_AUTHORITY
SCOPE = OWNER-SELECTED_MATCHED_TERRA_XHIGH_EVALUATION
```

## Purpose and narrow relationship

This amendment records a concrete, bounded predicate for an explicit owner-selected Terra XHigh evaluation. It narrowly supersedes only the prior statement that `STATIC_APPROVED_DAG` cannot represent Terra XHigh at all. It does not rewrite the existing architecture documents or broaden any other V1 authority.

Terra High remains the canonical default executor. The canonical P004 Terra High run at 300 seconds (`P004-CANONICAL-TERRA-HIGH-001`) produced `VALID_BLOCKED`; earlier P003 and P004 evidence also showed Terra High nonmatches.

## Approved matched treatment

The initially intended treatment is P004, with the same task, tool, scope, verifier, and time-budget authority as P004 N1, changing only effort:

```text
high → xhigh
```

`xhigh` exists only as an explicit owner-selected `STATIC_APPROVED_DAG` route. It is not a new default and cannot be selected by a model.

A future XHigh run still requires a separately approved exact launch-spec digest. Implementation capability does not authorize arbitrary future XHigh runs.

## Preserved prohibitions

```text
no automatic High → XHigh escalation
no automatic retry at XHigh
no retry, fallback, or substitution
no model-selected effort or routing
Terra Max remains unauthorized
no provider execution or real XHigh pilot under this amendment
```

A High failure must remain High-bound and block under its frozen authority; it cannot mutate effort or schedule an XHigh attempt. A High-approved launch digest cannot authorize XHigh, and an XHigh-approved launch digest cannot authorize High.

## Boundary

This amendment authorizes only representation of the stated owner-approved matched evaluation route. It does not authorize Terra Max, dynamic routing, planner/replan/closeout additions, Luna or Sol normal-path calls, durability or resume, a second launcher, benchmark-specific runtime behavior, publication, or push.
