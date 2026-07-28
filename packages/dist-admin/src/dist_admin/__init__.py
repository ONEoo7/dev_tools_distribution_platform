"""The admin plane (PLAN.md 8), scoped to the forge source registry.

What this service is allowed to do is most of what there is to say about it:

- It holds **no signing keys** and has no route to any. Registering a source
  does not sign anything and cannot be made to.
- It holds **no forge credential**. Everything it wants to know about a
  repository it learns by queueing a job for the ingest worker, which is the
  component that owns that credential and has no inbound listener.
- It **never mutates TUF metadata** (PLAN.md 8.2). A new application's
  `app-<id>` delegation is signed by `targets`, whose keys are offline, so a
  source it registers stops at `PENDING_DELEGATION` until a human runs the
  ceremony.

A full compromise of this service therefore yields the ability to queue jobs
that get audited, and to describe repositories nobody has agreed to trust.
"""
