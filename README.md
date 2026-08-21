```
 ⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⢰⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⣠⣶⣿⣿⣷⣶⡶⣶⣶⣆⠀⠀⠀⣴⣶⣶⠆
 ⠀⠀⠀⠉⢹⣿⣿⠉⠉⠀⠘⢿⣿⣧⣀⣾⣿⡿⠃⠀             Tiny, open, embeddable, native coding agent.
 ⠀⠀⠀⠀⣼⣿⡏⠀⠀⠀⠀⠀⠻⣿⣿⣿⠟⠀⠀⠀
 ⠀⠀⠀⢀⣿⣿⠃⠀⠀⠀⠀⢠⣦⠘⢿⣿⣷⡀⠀⠀             curl -fsSL https://fx.sh/setup.sh | bash
 ⠀⠀⠀⣸⣿⡟⠀⠀⠀⠀⣰⣿⣿⠗⠀⠻⣿⣿⣄⠀
 ⠀⠀⠀⣿⣿⠇⠀⠀⠀⠾⠿⠿⠋⠀⠀⠀⠘⠿⠿⠦             ⚠ Status: Experimental. Use at your own risk.
  ⠀⣸⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

fx is a coding agent harness and CLI written in Zig, optimized for research and embeddability as part of larger systems.

It focuses on minimalism and performance across the board, from system prompt design to its tools, feature set, and 7.8 MiB binary.

For end users, its CLI output style and form factor aim to be closer to a Unix shell than a heavy "IDE in the terminal" TUI.

It's open source (Apache-2.0), model-agnostic, and suitable for both local and cloud inference.

## Install

```bash
curl -fsSL https://fx.sh/setup.sh | bash
```

On Windows, download `fx-windows-x86_64.zip` from the
[latest release](https://github.com/vercel-labs/fx/releases/latest), extract it,
and put `fx.exe` somewhere on `PATH`:

```powershell
Expand-Archive fx-windows-x86_64.zip -DestinationPath $env:LOCALAPPDATA\fx
$env:PATH = "$env:LOCALAPPDATA\fx;$env:PATH"
```

Windows Terminal is recommended. fx turns on the console's ANSI interpreter
itself, so `conhost` works too.

## Run fx

To get started, sign in with Vercel:

```bash
fx login
```

Or add an AI Gateway API key:

```bash
fx setup
```

Run fx from a project:

```bash
cd your_project
fx
```

The current directory becomes the primary workspace. Enter a prompt, or run `/help` to browse interactive commands.

Run `/feedback` to open the feedback form at `fx.sh/feedback`. It does not create a diagnostic or change the clipboard.

Run `/trace` to create a private Markdown diagnostic with logs, session context, runtime state, permissions, and recent activity. On macOS, fx copies the `.md` file to the clipboard; on other platforms, it saves the file and prints its path. Review and redact the trace before sharing it.

Use `fx ask` for a single request:

```bash
fx ask "explain the changes in this repository"
```

fx starts in `auto` permission mode. Routine understood development actions run directly; unresolved sensitive actions receive one bounded automatic review. A blocked action may return an exact approval request that the agent can send to fx's real permission screen. Ordinary question text never grants permission. See [Permissions](https://fx.sh/docs/configure-fx/permissions) for other modes and persistent rules.

Inside a saved session, `/permissions remember <allow|deny> <tool-name> <arguments-json>` stores an exact confirmed rule without running the action. `/permissions` lists stable rule IDs, and `/permissions revoke <rule-id>` removes a stored rule even when its original workspace or file state has changed.

## Embed fx

fx builds as a native binary or WebAssembly. Applications embedding fx can provide network transport, session storage, configuration, permission handling, and terminal I/O.

| Surface | Use |
| --- | --- |
| `fx acp` | Connect the native agent to editors and other Agent Client Protocol clients. |
| `createFxAgent()` | Embed the agent core in a JavaScript host with `fx-core.wasm`. |
| `createFxTerminal()` | Embed the interactive terminal with `fx-term.wasm`. |

The WebAssembly SDK is experimental. See the [WebAssembly SDK](sdk/README.md) and [ACP documentation](https://fx.sh/docs/using-fx/acp).

## Extend fx

Add reusable instructions with [skills](https://fx.sh/docs/capabilities/skills), connect external tools through [MCP](https://fx.sh/docs/capabilities/mcp), or delegate independent work to [subagents](https://fx.sh/docs/capabilities/subagents). Project instruction files may link within their scope, and read-only workspace or compatibility skill directories may link within their owning workspace or home; managed skills, `SKILL.md` files, resources, and escaping links remain no-follow. `fx status` and `fx doctor` report an invalid trusted MCP profile without starting its servers.

## Documentation

Read the [fx documentation](https://fx.sh/docs).

## Build from source

Building fx requires [Zig 0.16.0+](https://ziglang.org/download/):

```bash
git clone https://github.com/vercel-labs/fx.git
cd fx
zig build -Doptimize=ReleaseSafe
./zig-out/bin/fx
```

Run the test suite with `zig build test`. See [CONTRIBUTING.md](CONTRIBUTING.md) for development and contribution guidelines.

The same commands build fx on Windows; the binary is `zig-out\bin\fx.exe`.

### Platform support

fx runs natively on macOS, Linux, and Windows x86_64. A few capabilities have no
Windows equivalent yet and report themselves as unavailable rather than failing
partway:

| Capability | Windows |
| --- | --- |
| Interactive terminal UI, sessions, file and shell tools | Supported |
| Workspace-relative paths | Reported with `/`, as git does, so transcripts stay portable; absolute paths keep native separators |
| Stored credentials | Encrypted with DPAPI for the current Windows user, in place of POSIX mode bits |
| Private state permissions | NTFS ACLs are inherited; POSIX mode bits are neither set nor verified |
| Command cancellation and timeout | A job object terminates the whole child process tree, in place of a POSIX process group |
| Shell tool | Commands run through `cmd /C` |
| Background commands | Unavailable |
| Hosted child terminals | Unavailable |
| `web_fetch` | Unavailable; the pinned-address transport is written against POSIX sockets |
| `fx upgrade` and auto-upgrade | Unavailable; install a new release manually |
| OS sandbox | Unavailable, as on Linux |

### Stored credentials

`fx login` and `fx setup` keep credentials under `~/.fx`, and how they are
protected follows what the platform provides without adding a dependency.

- **macOS** stores the API key in the Keychain.
- **Windows** encrypts both the signed-in session and the API key with DPAPI,
  scoped to the current user, so the bytes on disk are useless to another
  account. This replaces the `0600` file mode fx relies on elsewhere, which
  Windows cannot enforce. Set `FX_DISABLE_DPAPI=1` to store them unencrypted.
- **Linux** stores them in a `0600` profile file. The comparable service is
  libsecret, which needs D-Bus and a running keyring daemon; fx targets
  containers and agent sandboxes where neither is present, so there is no
  option that works everywhere fx runs.

A credential written before encryption existed still loads and is encrypted by
the next write. Encryption never falls back to plaintext: if it fails, the write
fails. A credential this account cannot decrypt is reported as unreadable, not as
missing, so the fix is to run `fx login` or `fx setup` again.

## License

[Apache-2.0](LICENSE)

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Credits

Interface sounds by [cuelume](https://github.com/Danilaa1/cuelume).
