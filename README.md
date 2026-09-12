# mcp-exposure

Lists the MCP servers registered in the AI clients on your machine and shows how each one is exposed.

```
$ mcp-exposure
xapi  claude-code/user  stdio  WARN
  npx -y @xdevplatform/xurl mcp https://api.x.com/mcp
  UNPINNED         @xdevplatform/xurl is fetched at every start with no exact version
  SECRET_INLINE    env.CLIENT_SECRET is stored in plaintext
```

Reads the config files of Claude Code, Claude Desktop, Cursor, VS Code and Gemini CLI. No root, no dependencies, one static binary. One block per server (name, client/scope, transport, verdict, then the command or URL and each finding), so it reads the same on any terminal width. Exit code is `1` when any server is `RED`.

## Install

```
go install github.com/nobu666/mcp-exposure@latest
```

## What it checks

| Finding | Level | Meaning |
|---|---|---|
| `UNPINNED` | warn | The server is started with `npx`, `bunx`, `uvx`, `pnpm dlx` or `pipx run` and the package has no exact version (`name@1.2.3`, `@scope/name@1.2.3`, `name==1.2.3`). `@latest`, `^1` and no version at all mean the registry decides what runs at every start. |
| `SECRET_INLINE` | warn / red | A value under a secret-looking key is stored as plaintext in `env` or `headers`. Keys are split into words (`API_KEY`, `apiKey`, `APIKey`) and flagged when a word is `key`, `secret`, `token`, `password`, `auth`, `authorization`, `bearer` or `credentials`; `KEYBOARD` and `AUTHOR` are not. Red when the file is tracked by git. Values that reference a variable (`${VAR}`, `${VAR:-x}`, `${env:VAR}`, `${input:x}`, `$VAR`), empty values, and file paths are not flagged. |
| `PLAINTEXT_REMOTE` | red | `http://` or `ws://` to a host that is not this machine. Headers and content travel in the clear. |
| `LISTEN_ALL` | red | A local HTTP/SSE server's port answers on a non-loopback address, so it is bound to `0.0.0.0` or `[::]`. The MCP spec says local servers SHOULD bind to `127.0.0.1` only. |
| `REBIND_OPEN` | red | The local server accepts a request whose `Host` and `Origin` are `evil.example`. A DNS-rebinding page can reach it from a browser. The spec says servers MUST validate `Origin`. |
| `AUTH_NONE` | warn | The local server accepted an `initialize` with no credentials. The spec says servers SHOULD authenticate. |
| `CONTAINER_ALIAS` | info | `host.docker.internal` resolves differently outside a container, so it is not probed. |
| `DOWN` | info | Nothing is listening on the configured local port. |

The spec references are from the Model Context Protocol specification, version 2026-07-28, Streamable HTTP transport, "Security Warning".

## How the local probe works

For a server whose URL points at this machine, it connects to the port on `127.0.0.1`, `::1` and every interface address to see where the socket is bound. Then it sends two requests to the configured URL: a plain one with a same-origin `Origin`, and one with `Host: evil.example` and `Origin: http://evil.example`. Streamable HTTP servers get a JSON-RPC `initialize` by POST; legacy `/sse` servers get a GET. Only the status codes are compared. Bodies are never read and nothing is written.

Remote servers (`https://`) are never probed. The table shows their transport and host, nothing more.

## Config files read

| Client | Project | User |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (user scope, plus per-project local scope) |
| Claude Desktop | | `~/Library/Application Support/Claude/claude_desktop_config.json` (`%APPDATA%\Claude\` on Windows, `~/.config/Claude/` on Linux) |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` | `~/Library/Application Support/Code/User/mcp.json` |
| Gemini CLI | `.gemini/settings.json` | `~/.gemini/settings.json` |

Project files are looked up in the current directory. Pass `--config path.json` to add any file with a `mcpServers` object. `--json` prints everything, including each finding's note.

## What it does not do

- It does not read Codex CLI's `config.toml`, or the `.mcp.json` files that Claude Code plugins bring along.
- It does not check the host firewall. `LISTEN_ALL` says the socket is bound to every interface, not that a neighbor can reach it.
- It does not ask any registry whether a package exists or is known to be malicious.
- It does not send anything to remote servers.
- `SECRET_INLINE` for an untracked file inside a repository is only a warning, even though `git add .` would commit it.

## License

MIT
