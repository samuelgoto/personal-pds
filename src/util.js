export function formatDid(hostname) {
  // did:web spec: port must be encoded as %3A
  const encoded = hostname.replace(':', '%3A');
  return `did:web:${encoded}`;
}
