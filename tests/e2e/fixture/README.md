# canary-shop (fixture)

A tiny repo for the real-agent job (`tests/e2e/real-agent.sh`). The job writes a `.env` with
fresh canary values next to this file in a temp copy, imports it with `ms import`, and asks a
real agent to look around. Nothing here is a real secret, and no `.env` is ever committed.

`charge.sh` shows how the app uses its Stripe key.
