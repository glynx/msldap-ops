"""Collection presets for bofhound.

Instead of one ``(objectClass=*)`` query the collection is split per object type, so that each
part can be run on its own and no single query returns the whole directory.

Base DNs are placeholders resolved from the RootDSE of the connected server, so the presets work
on child domains (Configuration and Schema NC live under the forest root) as well.
"""

from dataclasses import dataclass, field
from typing import List

ALL_WITH_SD = ['*', 'nTSecurityDescriptor']


@dataclass(frozen=True)
class PresetQuery:
	label: str
	filter: str
	base: str = '{domain}'
	attributes: List[str] = field(default_factory=lambda: list(ALL_WITH_SD))


@dataclass(frozen=True)
class ResolvedQuery:
	preset: str
	label: str
	filter: str
	base: str
	attributes: List[str]

	@property
	def wants_sd(self):
		return any(a.lower() == 'ntsecuritydescriptor' for a in self.attributes)


PKI = 'CN=Public Key Services,CN=Services,{config}'

PRESETS = {
	'domain': (
		'Domain object (required by bofhound for most other objects)',
		[PresetQuery('domain object', '(objectClass=domain)')],
	),
	'users': (
		'User accounts',
		[PresetQuery('users', '(sAMAccountType=805306368)')],
	),
	'computers': (
		'Computer accounts including gMSAs, and trust accounts',
		[
			# by account type instead of objectCategory=computer, so that gMSAs are included
			PresetQuery('computers and gMSAs', '(sAMAccountType=805306369)'),
			PresetQuery('trust accounts', '(sAMAccountType=805306370)'),
		],
	),
	'groups': (
		'Groups (security and distribution, including builtin groups)',
		[PresetQuery('groups', '(objectCategory=group)')],
	),
	'ous': (
		'Organizational units (Contains edges, GPO links)',
		[PresetQuery('OUs', '(objectClass=organizationalUnit)')],
	),
	'containers': (
		'Containers (Contains edges)',
		[PresetQuery('containers', '(&(objectClass=container)(!(objectClass=groupPolicyContainer)))')],
	),
	'gpos': (
		'Group policy objects',
		[PresetQuery('GPOs', '(objectClass=groupPolicyContainer)')],
	),
	'trusts': (
		'Domain trusts',
		[PresetQuery('trusts', '(objectClass=trustedDomain)')],
	),
	'fsps': (
		'Foreign security principals (members from trusted domains)',
		[PresetQuery('foreign security principals', '(objectClass=foreignSecurityPrincipal)')],
	),
	'schema': (
		'Schema GUIDs (LAPS, KeyCredentialLink and inherited ACEs)',
		[PresetQuery('schema GUIDs', '(schemaIDGUID=*)', '{schema}', ['name', 'schemaIDGUID'])],
	),
	'adcs': (
		'ADCS: enterprise CAs, root/AIA CAs, NTAuth store, templates, issuance policies',
		[
			PresetQuery('enterprise CAs', '(objectClass=pKIEnrollmentService)', PKI),
			PresetQuery('root CAs, AIA CAs, NTAuth store', '(objectClass=certificationAuthority)', PKI),
			PresetQuery('certificate templates', '(objectClass=pKICertificateTemplate)', PKI),
			PresetQuery('issuance policies', '(objectClass=msPKI-Enterprise-Oid)', PKI),
		],
	),
	'partitions': (
		'crossRefs with the NetBIOS domain names',
		[PresetQuery('NetBIOS names', '(netbiosname=*)', 'CN=Partitions,{config}', ['*'])],
	),
	'dns': (
		'DNS nodes from DomainDnsZones and ForestDnsZones (computer IP addresses, can be large)',
		[
			PresetQuery('DNS nodes (domain zones)', '(objectClass=dnsNode)', 'DC=DomainDnsZones,{domain}', ['objectClass', 'distinguishedName', 'name', 'dnsRecord']),
			PresetQuery('DNS nodes (forest zones)', '(objectClass=dnsNode)', 'DC=ForestDnsZones,{forest}', ['objectClass', 'distinguishedName', 'name', 'dnsRecord']),
		],
	),
}

# what 'bofhound_collect all' runs; dns is left out because it can be large
ALL = ['domain', 'users', 'computers', 'groups', 'ous', 'containers', 'gpos', 'trusts', 'fsps', 'schema', 'adcs', 'partitions']


def naming_contexts(serverinfo, default_tree=None):
	"""Base DN placeholders from the RootDSE (as returned by msldap's get_serverinfo)."""
	serverinfo = serverinfo or {}
	domain = serverinfo.get('defaultNamingContext') or default_tree
	if not domain:
		raise ValueError('The default naming context is unknown, log in first')
	forest = serverinfo.get('rootDomainNamingContext') or domain
	config = serverinfo.get('configurationNamingContext') or 'CN=Configuration,%s' % forest
	schema = serverinfo.get('schemaNamingContext') or 'CN=Schema,%s' % config
	return {'domain': domain, 'forest': forest, 'config': config, 'schema': schema}


def resolve(names, serverinfo, default_tree=None):
	"""Expands preset names ('all' allowed) into concrete queries, in the given order."""
	expanded = []
	for name in names:
		name = name.lower()
		if name == 'all':
			expanded.extend(n for n in ALL if n not in expanded)
		elif name not in PRESETS:
			raise ValueError("Unknown preset '%s', available: all, %s" % (name, ', '.join(PRESETS)))
		elif name not in expanded:
			expanded.append(name)

	contexts = naming_contexts(serverinfo, default_tree)
	queries = []
	for name in expanded:
		for q in PRESETS[name][1]:
			queries.append(ResolvedQuery(name, q.label, q.filter, q.base.format(**contexts), list(q.attributes)))
	return queries
