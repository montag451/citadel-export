# Installation #

Just copy one of the pre-compiled binary available
[here](https://github.com/montag451/citadel-export/releases/latest) on
your machine (preferably in a location contained in your PATH) and you
are done. If you feel adventurous or you don't like using binaries not
compiled by you, you can compile the binary from sources. To do so,
you need to install the [Go toolchain](https://golang.org/dl/). Once
the go toolchain is installed on your machine, execute `go get -u
github.com/montag451/citadel-export`. The binary will be installed in
the `bin` directory of your `GOPATH` (use `get env GOPATH` to find out
the value of `GOPATH` on your machine)

# Usage #

`citadel-export` is a CLI tool so it must be used from a terminal or a
console. Type `citadel-export -h` to find out the options that the
command understands. The required options are:

- `email`
- `room-name` or `room-id`
- `output-dir`

The option `output-dir` specify a directory where the result of the
export will be stored. It will contain a file named `messages.html`
that will contain all the messages published in the room and a
directory `files` that will contains all the files uploaded in the
room. You can re-use the same `output-dir` to export a room
incrementally.
