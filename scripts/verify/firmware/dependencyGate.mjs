export const assertRequiredDependencies = (provider, requiredCommands) => {
  if (provider === null || typeof provider !== "object")
    throw new Error("Unblob dependency inventory is malformed");

  const inventory = provider;
  if (
    inventory.provider_id !== "unblob" ||
    inventory.dependency_inventory_coverage !== "native_reported" ||
    !Array.isArray(inventory.dependencies) ||
    !Array.isArray(inventory.unparsed_dependency_lines) ||
    inventory.unparsed_dependency_lines.length !== 0
  )
    throw new Error("Unblob dependency inventory is incomplete or malformed");

  const seen = new Set();
  for (const row of inventory.dependencies) {
    if (
      row === null ||
      typeof row !== "object" ||
      typeof row.command !== "string" ||
      row.command.length === 0 ||
      typeof row.reported_installed !== "boolean" ||
      seen.has(row.command)
    )
      throw new Error("Unblob dependency inventory is malformed or ambiguous");
    seen.add(row.command);
  }

  for (const command of requiredCommands) {
    if (typeof command !== "string" || command.length === 0)
      throw new Error("Required Unblob dependency name is malformed");
    const rows = inventory.dependencies.filter(
      (row) => row.command === command,
    );
    if (rows.length !== 1)
      throw new Error(`Required Unblob dependency is absent: ${command}`);
    if (!rows[0].reported_installed)
      throw new Error(`Required Unblob dependency is missing: ${command}`);
  }

  return [...requiredCommands];
};
