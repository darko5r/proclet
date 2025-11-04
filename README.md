# proclet

**proclet** is a tiny Linux process sandbox written in Rust.  
It launches a command inside **new PID + mount namespaces** with a **fresh `/proc`** — no containers required.
