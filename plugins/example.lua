-- Example PowerSVX Lua plugin.
-- Return: "continue" | "nxdomain" | "nodata" | "refused"
function on_query(name, qtype, client_ip)
  if name == "plugin-block.test." then
    return "nxdomain"
  end
  return "continue"
end
