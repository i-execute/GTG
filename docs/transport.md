# Transport and lifecycle

The transport helpers expose packet construction and bounded request behavior. They do not provide a complete autonomous transport loop, reconnection worker, or production session manager.

Callers remain responsible for endpoint selection, connection ownership, cancellation, and credential handling.
