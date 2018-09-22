[![Build Status](https://travis-ci.org/Equidamoid/debus.svg?branch=master)](https://travis-ci.org/Equidamoid/debus)
## debus: a non-reference DBus implementation

## Summary
This is an attempt to make a nice-to-use asynchronous DBus implementation without any extra dependencies and magic.

## Why?
There are two main issues with using "the" dbus implementation with python:
 - magical dependencies ("what is `import gi` and how do I get it to work on my embedded device?")
 - foreign event loop mandatory for certain operations*, while in the end we only need ot read/write to a socket

\* AFAIR you can do synchronous calls wihtout the event loop, but definitely can't subscribe to signals without it

## Dependecies
debus uses cython. Thus, you need it (and a working build environment for C) to build debus.

At runtime no extra dependencies (except python itself) is needed.

## Known limitations

 - Only little-endian messages are supported so far
 - Methods have to return a tuple to match dbus idea of multiple "out" parameters
