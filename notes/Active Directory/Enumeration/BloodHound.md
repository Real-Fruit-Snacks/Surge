---
tags:
  - Active_Directory
  - BloodHound
  - Discovery
  - Enumeration
  - Foundational
  - Windows
---

## Cypher Queries (Neo4j Interface)
resources: [Custom Queries](https://github.com/hausec/Bloodhound-Custom-Queries)

> [!info] Access Neo4j directly at `http://localhost:7474` for custom queries. Or use **Hackles**: `python -m hackles -c query.cypher`

### Owned Objects

#### List All Owned Users
```cypher
MATCH (m:User) WHERE m.owned=TRUE RETURN m
```

#### List All Owned Computers
```cypher
MATCH (m:Computer) WHERE m.owned=TRUE RETURN m
```

#### List All Owned Groups
```cypher
MATCH (m:Group) WHERE m.owned=TRUE RETURN m
```

#### List Groups of Owned Users
```cypher
MATCH (m:User) WHERE m.owned=TRUE WITH m MATCH p=(m)-[:MemberOf*1..]->(n:Group) RETURN p
```

### High Value Targets

#### List High Value Targets
```cypher
MATCH (m) WHERE m.highvalue=TRUE RETURN m
```

#### High Value Target Groups
```cypher
MATCH p=(n:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN p
```

### Attack Paths

#### Find Shortest Path to Domain Admin
```cypher
MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@<DOMAIN>"})) RETURN p
```

#### Find All Domain Admins
```cypher
MATCH (n:Group) WHERE n.name =~ "(?i).*DOMAIN ADMINS.*" RETURN n
```

### Kerberos Attacks

#### Find All Kerberoastable Users
```cypher
MATCH (n:User) WHERE n.hasspn=true RETURN n
```

```cypher
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames
```

#### Kerberoastable Users with Old Passwords
> Find all Kerberoastable Users with passwords last set less than 5 years ago.

```cypher
MATCH (u:User) WHERE u.hasspn=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name, u.pwdlastset order by u.pwdlastset
```

#### Kerberoastable Users with Path to DA
```cypher
MATCH (u:User {hasspn:true}) MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = shortestPath( (u)-[*1..]->(g) ) RETURN p
```

#### Kerberoastable Users in High Value Groups
```cypher
MATCH (u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.highvalue=true AND u.hasspn=true RETURN u
```

#### Kerberoastable Users and AdminTo
```cypher
OPTIONAL MATCH (u1:User) WHERE u1.hasspn=true OPTIONAL MATCH (u1)-[r:AdminTo]->(c:Computer) RETURN u
```

#### Find AS-REP Roastable Users
```cypher
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

### Delegation

#### Find Computers with Unconstrained Delegation
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

```cypher
MATCH (c:Computer {unconstraineddelegation:true}) return c
```

#### Unconstrained Delegation (Non-DC)
> Find computers that allow unconstrained delegation that are not domain controllers.

```cypher
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2
```

#### Constrained Delegation
```cypher
MATCH p=(u:User)-[:AllowedToDelegate]->(c:Computer) RETURN p
```

#### Computers with Constrained Delegation Targets
```cypher
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c
```

### Permissions and Rights

#### Find Users with DCSync Rights
```cypher
MATCH p=(n)-[:GetChanges|GetChangesAll|GenericAll|WriteDacl|Owns]->(d:Domain) RETURN p
```

#### Groups That Can Reset Passwords
> Warning: Heavy query.

```cypher
MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN p
```

#### Groups with Local Admin Rights
> Warning: Heavy query.

```cypher
MATCH p=(m:Group)-[r:AdminTo]->(n:Computer) RETURN p
```

#### All Users with Local Admin Rights
```cypher
MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN p
```

### RDP Access

#### Domain Users RDP Access
```cypher
match p=(g:Group)-[:CanRDP]->(c:Computer) where g.objectid ENDS WITH '-513' return p
```

#### Groups with RDP Access
```cypher
MATCH p=(m:Group)-[r:CanRDP]->(n:Computer) RETURN p
```

### Sessions

#### Domain Admin Sessions
```cypher
MATCH (n:User)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(n) return p
```

#### Find Active Sessions
```cypher
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

### Computer Queries

#### List All Computers
```cypher
MATCH(m:Computer) RETURN m
```

#### Computers with Unsupported OS
```cypher
MATCH (H:Computer) WHERE H.operatingsystem =~ '.*(2000|2003|2008|xp|vista|7|me)*.' RETURN H
```

#### Computers with MSSQL SPNs
```cypher
MATCH (c:Computer) WHERE ANY (x IN c.serviceprincipalnames WHERE toUpper(x) CONTAINS 'MSSQL') RETURN c
```

### User Queries

#### List All Users
```cypher
MATCH(m:User) RETURN m
```

#### Users Logged In Within 90 Days
```cypher
MATCH (u:User) WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u
```

#### Passwords Set Within 90 Days
```cypher
MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (90 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] RETURN u
```

#### Users Never Logged On (Active Accounts)
```cypher
MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n
```

### GPO Queries

#### View All GPOs
```cypher
Match (n:GPO) RETURN n
```

#### Domain User GPO Permissions
> Find if any domain user has interesting permissions against a GPO. Warning: Heavy query.

```cypher
MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p
```

### Group Queries

#### Groups Containing Admin
```cypher
Match (n:Group) WHERE n.name CONTAINS 'ADMIN' RETURN n
```

#### Groups with Users and Computers
```cypher
MATCH (c:Computer)-[r:MemberOf*1..]->(groupsWithComps:Group) WITH groupsWithComps MATCH (u:User)-[r:MemberOf*1..]->(groupsWithComps) RETURN DISTINCT(groupsWithComps) as groupsWithCompsAndUsers
```

#### Users in VPN Group
```cypher
Match p=(u:User)-[:MemberOf]->(g:Group) WHERE toUPPER (g.name) CONTAINS 'VPN' return p
```

#### Unprivileged Users with AddMember Rights
```cypher
MATCH (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) RETURN p
```

### Cross-Domain Queries

#### Object with Foreign Domain Rights
```cypher
MATCH p=(n)-[r]->(m) WHERE NOT n.domain = m.domain RETURN p
```

#### Sessions in Specific Domain
```cypher
MATCH p=(m:Computer)-[r:HasSession]->(n:User {domain:{result}}) RETURN p
```

### Database Management

#### Delete All Data
```cypher
match (a) -[r] -> () delete a, r
match (a) delete a
```
