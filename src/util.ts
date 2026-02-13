export function formatDid(hostname: string): string {
  // did:web spec: port must be encoded as %3A
  const encoded = hostname.replace(':', '%3A');
  return `did:web:${encoded}`;
}
