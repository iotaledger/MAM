# MAM
Masked Authentication Messaging

## What is it?
It's a little library that signs and encrypts, decrypts and authenticates, data that you wish to publish to the tangle.

You could publish messages intermittently, and someone else could subscribe to them by the key that you give them.

The channel keys are the merkle root of the set of one-time keys used to sign the messages. 
You could have any size of tree that you like, and it is just derived from your seed.

## How do I use it?
Say you have a love letter. First, convert your love letter from ascii to trytes, 
and then couple that with your seed (your super secret key), 
and some message-organizing numbers, and run that through `mam::create`.
This will return a payload ready to go into a transaction, and the key to unlock it.

Since you're keeping track of those message-organizing numbers (one of them is an index), 
you can get a message id from `mam::message_id` using the key and this index (converted to trits).
Create a transaction with your payload as the message, and this message id as the address,
and publish it to the tangle.

If you have a key given to you from someone else, just try getting the message id as above,
starting at index 0, and query the tangle by that address. Given a masked payload, you can
try to get the underlying message using `mam::parse` with the payload, this key, and the index
you used to find it. If successful, it will return to you the message, as well as the following 
key. 

## I want more information
More will come in time.

## build

It is suggested to use rust nightly. To build the project for release (optimized), run

```
cargo build --all --release
```

To build javascript (asm or wasm), follow instructions from [here](https://www.hellorust.com/setup/emscripten/), and then

```
cd bindings
# and then
cargo build --release --target wasm32-unknown-emscripten
# or
cargo build --release --target asmjs-unknown-emscriptenw
```

The compiled output is found in the `target` directory.
