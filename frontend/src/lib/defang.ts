/**
 * Defangs a URL or IP for safe display to prevent accidental clicks or link previews (HC-16).
 * Transforms http:// -> hxxp://, https:// -> hxxps://, and replaces dots in domain with [.]
 */
export function defang(input: string): string {
  if (!input) return "";
  let defanged = input
    .replace(/^https:\/\//i, "hxxps://")
    .replace(/^http:\/\//i, "hxxp://");

  const slashIdx = defanged.indexOf("/", 8);
  if (slashIdx !== -1) {
    const hostPart = defanged.slice(0, slashIdx).replace(/\./g, "[.]");
    return hostPart + defanged.slice(slashIdx);
  }
  return defanged.replace(/\./g, "[.]");
}
