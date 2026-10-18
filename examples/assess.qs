# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# shaka's Active Directory assessment pipeline.
#
#     shaka script run examples/assess.qs
#
# shaka runs against the built-in offline demo directory here: no live LDAP,
# no authorization. Live assessment requires an in-scope directory endpoint.

# Use the offline demo directory (no network).
set assess.sim -> "true"

# Run the full assessment pipeline: discover->enumerate->graph->analyze->
# findings->risk. A specific capability id (for example "shaka.users.enumerate")
# runs the same full pipeline, which covers that module.
run assess

# Read live properties from the completed run via $(...).
echo -> "session   = $(session.id)"
echo -> "domains   = $(result.domains)"
echo -> "dcs       = $(result.dcs)"
echo -> "computers = $(result.computers)"
echo -> "users     = $(result.users)"
echo -> "groups    = $(result.groups)"
echo -> "trusts    = $(result.trusts)"
echo -> "nodes     = $(result.nodes)"
echo -> "findings  = $(result.findings)"
echo -> "risk      = $(result.risk_score)/100 ($(result.risk_level))"

# Show capability metadata and write a JSON session report.
show shaka.findings.list
report -> "shaka-report.json"

echo -> "done"
