/**
 * Deny-path leaf kinds, shared by every adapter that has to MATERIALIZE a deny
 * path that does not exist yet.
 *
 * Two platforms need a real filesystem object before their deny mechanism can
 * cover a name:
 *
 *   - Windows: an AppContainer DENY ace needs an object to attach to.
 *   - Linux:   bwrap needs a mount point to place `--tmpfs` / `--ro-bind` over,
 *              and a deny path sitting inside a read-write bind is otherwise
 *              creatable by the sandboxed process (`mkdir ~/.ssh && echo <key>
 *              > authorized_keys` goes straight through to the host).
 *
 * Materializing with the WRONG kind is not a cosmetic error and not recoverable
 * by the user: creating `~/.gitconfig` as a directory makes every later
 * `git config --global …` fail with "could not lock config file … Is a
 * directory", and the same shape breaks `~/.npmrc` (npm EISDIR) and `~/.bashrc`
 * / `~/.zshrc` (the shell errors sourcing a directory) - outside the app,
 * permanently, with nothing in the app to undo it.
 *
 * `path.extname` is no help: it reports "" for `.zshrc`, `.gitconfig` AND
 * `.ssh` alike, so every dot-suffix heuristic guesses wrong on exactly the
 * names that matter. The kind is therefore caller-supplied first, with this
 * table as the fallback for callers not yet updated.
 *
 * What an UNRESOLVABLE kind means is the caller's call, and the two platforms
 * differ because the price differs (the split is spelled out on
 * `denyPathKinds` in types.ts):
 *
 *   - Windows must REFUSE the spawn: it creates the leaf on the host, so a
 *     guess it gets wrong breaks the user's tooling outside the app.
 *   - Linux may fall back to a tmpfs directory: it creates nothing on the host,
 *     because the leaf materializes on the sealed anchor's tmpfs, so the kind
 *     only selects which inert object the SANDBOX sees.
 */

/** Leaf names whose kind is well established across the platforms we support. */
export const WELL_KNOWN_DENY_LEAF_KINDS: Readonly<Record<string, "file" | "dir">> = {
  ".ssh": "dir",
  ".gnupg": "dir",
  ".aws": "dir",
  ".azure": "dir",
  ".kube": "dir",
  ".docker": "dir",
  ".convira": "dir",
  ".config": "dir",
  keychains: "dir",
  launchagents: "dir",
  launchdaemons: "dir",
  ".npmrc": "file",
  ".pypirc": "file",
  ".netrc": "file",
  ".zshrc": "file",
  ".zprofile": "file",
  ".zshenv": "file",
  ".bashrc": "file",
  ".bash_profile": "file",
  ".profile": "file",
  ".gitconfig": "file",
};

/**
 * Resolve a deny leaf's kind, caller-supplied first. `null` = unresolvable: the
 * caller decides, and must never read it as "file" by accident. A caller that
 * MATERIALIZES the leaf on the host (Windows) has to refuse the spawn; a caller
 * that only places a mount over a sealed tmpfs (Linux) may pick its own inert
 * default.
 */
export function resolveDenyLeafKind(
  denyPath: string,
  kinds: Record<string, "file" | "dir"> | undefined,
): "file" | "dir" | null {
  const explicit = kinds?.[denyPath];
  if (explicit) return explicit;
  const leaf = denyPath
    .replace(/[\\/]+$/u, "")
    .split(/[\\/]/u)
    .pop();
  if (!leaf) return null;
  return WELL_KNOWN_DENY_LEAF_KINDS[leaf.toLowerCase()] ?? null;
}
