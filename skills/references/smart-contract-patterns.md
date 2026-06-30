# Forge Smart Contract Patterns (.foz)

These patterns illustrate the standard implementation of contracts on the **Zephyria ZVM** using the **Forge language**. 

> [!IMPORTANT]
> - Zephyria ZVM is a register-based RISC-V VM. 
> - Forge uses Python-standard significant whitespace (indentation).
> - Never write contracts in Zig; use `.foz` for production contract development.

## 1. ZRC-20 Fungible Token Pattern

```forge
version 1

contract ZRC20:
    has:
        balances is Map[Address → u256]
        allowances is Map[Address → Map[Address → u256]]
        totalSupply is u256
    
    event Transfer(from is Address, to is Address, amount is u256)
    event Approval(owner is Address, spender is Address, amount is u256)

    action transfer(to is Address, amount is u256) gives bool:
        let from_bal = mine.balances[caller]
        need from_bal >= amount else "Insufficient balance"
        
        mine.balances[caller] -= amount
        mine.balances[to] += amount
        
        tell Transfer(from=caller, to=to, amount=amount)
        give back yes

    action approve(spender is Address, amount is u256) gives bool:
        mine.allowances[caller][spender] = amount
        tell Approval(owner=caller, spender=spender, amount=amount)
        give back yes

    view balance_of(owner is Address) gives u256:
        give back mine.balances[owner]
```

## 2. Access Control & Authority

```forge
version 1

contract ManagedSystem:
    authorities:
        admin_auth is AdminAuthority initially deployer
    
    has:
        roles is Map[Bytes32 → Map[Address → bool]]
    
    action grant_role(role is Bytes32, account is Address):
        only admin_auth
        mine.roles[role][account] = yes
    
    guard only_minter:
        need mine.roles["MINTER"][caller] else "Unauthorized: Minter role required"
```

## 3. ZRC-721 Non-Fungible Token Pattern

```forge
version 1

contract ZRC721:
    has:
        owners     is Map[u256 → Address]
        balances   is Map[Address → u32]
        token_uris is Map[u256 → String]
    
    action mint(to is Address, id is u256, uri is String):
        need not exists(mine.owners[id]) else "Already minted"
        
        mine.owners[id] = to
        mine.balances[to] += 1
        mine.token_uris[id] = uri
        
        tell Transfer(from=zero_address, to=to, id=id)

    action transfer(from is Address, to is Address, id is u256):
        need mine.owners[id] == caller or is_approved(caller, id) else "Unauthorized"
        need mine.owners[id] == from else "Not owner"
        
        mine.owners[id] = to
        mine.balances[from] -= 1
        mine.balances[to] += 1
```

## 4. Reentrancy Protection

```forge
version 1

contract Vault:
    has:
        locked is bool = no

    action withdraw(amount is u256):
        need not mine.locked else "Locked: Reentrancy detected"
        mine.locked = yes
        
        // interactions
        pay amount caller
        
        mine.locked = no
```
