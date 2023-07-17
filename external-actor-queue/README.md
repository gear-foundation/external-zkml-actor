# external-actor
External actor template

## handling flow

This actor relays messages to some external actor.

While on initialize, it accepts `io::Initalization` with actor code hash and actor initial state hash.

Next, it accepts `io::Incoming::New` for some message payload that will be put in the internal queue. When
actual external actor sends reply to this message via `io::Incoming::Proof`, the original message gets verified
reply.

Only thing to implement for actual implementation is `validate` function that will actually verify the external
actor proof and proceed with message reply mentioned above in case of success.

