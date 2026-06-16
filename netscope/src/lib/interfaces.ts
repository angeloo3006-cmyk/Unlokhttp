import type { Interface } from "@/lib/tauri";

export function interfaceDisplayName(value: string | null | undefined, interfaces: Interface[] = []) {
  if (!value) return "No interface selected";

  const normalizedValue = normalizeInterfaceName(value);
  const direct = interfaces.find(
    (networkInterface) =>
      networkInterface.name === value
      || networkInterface.desc === value
      || normalizeInterfaceName(networkInterface.name) === normalizedValue
      || normalizeInterfaceName(networkInterface.desc) === normalizedValue,
  );
  if (direct) return direct.desc || direct.name;

  const guid = extractNpcapGuid(value);
  if (guid) {
    const byGuid = interfaces.find((networkInterface) => networkInterface.name.includes(guid));
    if (byGuid) return byGuid.desc || byGuid.name;
    return `Adapter ${guid.slice(0, 8).toUpperCase()}`;
  }

  return value;
}

export function interfaceCaptureName(networkInterface: Interface | undefined) {
  if (!networkInterface) return "interface-0";
  return networkInterface.desc || networkInterface.name || `interface-${networkInterface.id}`;
}

function extractNpcapGuid(value: string) {
  const match = value.match(/NPF_\{([^}]+)\}/i);
  return match?.[1] ?? null;
}

function normalizeInterfaceName(value: string | null | undefined) {
  return (value ?? "").replace(/^\\Device\\NPF_/i, "NPF_");
}
