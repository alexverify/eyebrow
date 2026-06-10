// Package audit will define the runtime event model and a local spool for
// Component 2/3.
//
// Planned design: a typed Event (tool-call inspections and egress connections),
// an append-only local spool that survives restarts, and a batched submitter to
// the control plane (see internal/client) when a team opts in. Events are the
// raw material for the dashboard's audit timeline and drift alerts. Not yet
// implemented.
package audit
