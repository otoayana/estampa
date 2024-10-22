# estampa 📬

[![builds.sr.ht status](https://builds.sr.ht/~nixgoat/estampa.svg)](https://builds.sr.ht/~nixgoat/estampa?)

estampa is a server for the Misfin protocol. Written in Rust, and
powered by Tokio and rustls, it aims to provide an alternative, stable
implementation for the protocol with a minimalist design.

## Install

Clone this repository using `git`, and check out to the latest tagged
release.

```
$ git clone https://git.sr.ht/~nixgoat/estampa
$ cd estampa
$ git checkout v0.1.2
```

Build and install estampa using [`cargo`](https://rustup.rs/).

```
$ cargo install --path .
```

Copy and rename `contrib/config.example.toml` into `config.toml` within
your working directory. Open it with your preferred text editor (in
this example `hx` will be used).

```
$ cp contrib/config.example.toml config.toml
$ hx config.toml
```

Finally, start up the server.

```
$ estampa
```

Congrats! You should now have an estampa server fully up and running!
It is highly recommended to run this as a system service. An example
for a `systemd` service file is provided at `contrib/estampa.service`.

## Contributing

Send patches to [the mailing list](https://lists.sr.ht/~nixgoat/public-inbox). prefix patches
with "`[PATCH estampa]`".

See [the guide to `git send-email`](https://git-send-email.io) if this is your first time using
sourcehut.

## License

estampa is licensed under the GNU Affero General Public License,
version 3 or later. Refer to [the license](LICENSE) for details.
