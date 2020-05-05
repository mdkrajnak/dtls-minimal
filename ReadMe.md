*WARNING!* This project currently builds but has an unresolved bug.

# About

dtls-minimal is a simple example of how to setup a service that
includes DTLS support using libcoap2

I started with [libcoap-minimal](https://github.com/obgm/libcoap-minimal)
by Olaf Bergmann and added DTLS support and few not-minimal flourishes
(for example: CLI options)

This repository consists of two sample programs, one server with
DTLS enabled, and one without. Both servers provide a "Echo" service
and may be tested using the coap-client provided in the libcoap2
examples.

# Building

This example was built with [libcoap-2 4.2.1](https://github.com/obgm/libcoap)
with OpenSSL providing the SSL engine.

The project has an out-of-source set of cmake files. Once libcoap2
is installed and the project is cloned into $PROJECT the programs
can be built using cmake:

    mkdir $PROJECT/build
    cd $PROJECT/build
    cmake ../cmake
    cmake --build .

Use "cmake ../cmake -G Ninja" to use Ninja or "cmake ../cmake -DCMAKE_BUILD_TYPE=Debug"
for a debug build.

The build process has been run on Ubuntu 19.04 with cmake 3.13.

The as build files will be in $PROJECT/build/dtls-server/dtls-server
and $PROJECT/build/coap-server/coap-server.

# Running

To run *without* DTLS, run the server in one terminal window:

    $PROJECT/build/coap-server/coap-server

And in the other, run coap-client. Assuming coap-client is installed
in the default location:

    /usr/local/bin/coap-client -m post coap://127.0.0.1/Echo -e MyMessage

And the text "MyMessage" should be printed out in the console.

You can add "-v 9" to enable full debugging output on coap-client.

To run *with* DTLS:

    $PROJECT/build/dtls-server/dtls-server -c $PROJECT/tools/selfsigned.pem

Then run coap-client as before but use "coaps" for the protocol:

    /usr/local/bin/coap-client -m post coaps://127.0.0.1/Echo -e MyMessage

And the text "MyMessage" should be printed out in the console.

# Additional Notes

The DTLS configuration for the dtls-server is set up so that no
client authentication is required. The primary purpose of this setup
is to create an encrypted link to prevent man-in-the middle intercepts,
and not provide authentication.

The format of the certificate file has the private key and certificate in
one file, a format that follows what the libcoap2 coap-server example
uses. This project includes a script, mkselfsigned.sh, that will
create a new self-signed certificate that can be used.
