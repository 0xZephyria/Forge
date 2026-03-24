# The Definitive Forge Language Guide

*(An In-Depth Reference from Beginner to Advanced)*

Welcome to **Forge**, the natively-compiled, highly-parallel, and intensely secure smart contract language built exclusively for the Forge Blockchain. 

Forge abandons the confusing syntax of legacy contract languages (like Solidity or Rust) in favor of **readable, intent-driven English-like syntax**. If your code reads like what it does, audits are faster, bugs are fewer, and your developers can focus on product over boilerplate.

This guide acts as the single source of truth for Forge developers. It covers the core philosophy, deep architectural decisions, the strict type and authority checkers, and high-performance parallel execution mechanisms built natively into the compiler.

---

## Part 1: Architecture and Zero-Conflict Philosophy

Before writing a line of Forge, it is critical to understand the architecture of the Forge blockchain.

### Zero-Conflict Architecture
Forge guarantees **Zero-Conflict** parallel execution out-of-the-box. Instead of relying on a global messy state, Forge uses an **Isolated Account System**. 

- **State is segmented** into independent sub-accounts (Wallets, Programs, Vaults).
- The compiler (**`forgec`**) mathematically proves which accounts an `action` touches via the `checker.zig` semantic analyzer.
- Transactions modifying different accounts can process simultaneously without locking.

### Readable but Strict
Do not confuse Forge's readable syntax with leniency. The `checker.zig` and `types.zig` compiler modules enforce rigid constraints:
1. **Undeclared = Inaccessible:** You must explicitly declare any account you intend to read or write.
2. **Read-Only Enforcement:** If an account is declared `readonly`, any attempt to write to it will halt compilation.
3. **Capability Constraints:** You state exactly what a contract `can read/write` down to the specific field level.
4. **Cross-Program Isolation:** A program cannot write to an account owned by *another* program.

---

## Part 2: The Anatomy of a Forge Contract

A Forge contract is an encapsulated logical unit that declares state, defines strict authorities, sets up initial values, and provides actions and views.

### Structure Overview

Every `.foz` file follows a deeply structured layout enforced by the parser:

```forge
version 1                 // 1. Language Version (Mandatory)

use std.math              // 2. Imports (Optional)
define MAX_USERS as 1000  // 3. Global Constants (Optional)

contract Token:           // 4. Contract Definition
    
    // -> State Declarations
    accounts: ...         // Explicit access to external accounts
    has: ...             // Internal state stored in this program
    config: ...          // Immutable deployment configurations
    computed: ...        // Derived getter fields
    
    // -> Privilege Declarations
    authorities: ...      // Who holds power here (no hidden admins)
    
    // -> Initialization
    setup(): ...          // Constructor logic
    
    // -> Logic
    action mint(): ...    // State-changing functions
    view get_supply(): ... // Read-only functions
    pure add_math(): ...  // Pure functions (no state read/write)
    
    // -> Interfaces & Output
    event Minted(...)     // Emittable logs
    error CustomErr(...)  // Typed errors

The accounts: Block (External State)
Because Forge uses isolated accounts, you must declare what external data you bring into scope.
    accounts:
        treasury is Vault owned_by this
        oracle   is Data  global readonly
        user_acc is Data  child_of params.user can: write balance, read all_fields

The has: Block (Internal State)
This is where the contract's own data lives. You access these variables via the mine keyword (e.g., mine.total_supply).
    has:
        total_supply is u256
        balances     is Map[Account -> u256]
        is_active    is bool

The setup(): Block (Constructor)
The setup block runs exactly once upon deployment. Use it to initialize variables.
    setup():
        mine.total_supply = 0
        mine.is_active = yes

Part 3: The Forge Type System
Forge's type system is highly expressive but mathematically bounded. To run computations on a global blockchain efficiently, types are strictly sized.
Primitive Types
All numeric paths are protected against overflow/underflow by default via the parser and checker. There is no silent wrapping.
 * Unsigned Integers: u8, u16, u32, u64, u128, u256.
   * uint is an alias for u256 heavily used in token arithmetic.
 * Signed Integers: i8, i16, i32, i64, i128, i256.
   * int is an alias for i256.
 * Fixed-Point Arithmetic: Fixed[N], price9, price18, percent. (e.g. percent is Fixed[4])
 * Booleans: bool, with literals yes and no.
Time Types
Forge natively understands time. You do not need confusing manual unix-math. Time types include Timestamp, Duration, BlockNumber, Epoch, and Slot.
    action timeout_check(duration is Duration):
        need duration >= 30 days else "Too short"
        mine.unlock = now() plus duration

Cryptographic Types
Addresses are rigorously subdivided to establish origin safety:
 * Account: Any valid 32-byte address.
 * Wallet: A user-controlled account (sub-type of Account).
 * Program: A smart contract account (sub-type of Account).
 * System: System-level administrative accounts.
Other hashing types include Hash, Commitment (for ZK hiding), Signature, and PublicKey (for verifying BLS12-381 natively).
Composite Types
Complex structures ensure logic is bounded:
 * maybe Type: Replaces the concept of null. Can be nothing or something(...).
 * Result[Ok, Err]: For explicit error propagation without blowing up state changes.
 * Map[Key -> Value]: On-chain hashmap.
 * EnumMap[Key -> Value]: Iterable dictionaries.
 * List[Type] and Set[Type]: Bounded on-chain collections.
Custom Types
You define business logic records using struct, record, enum, or alias.
    struct UserInfo:
        balance  is u256
        is_admin is bool = no
        
    enum Status:
        Pending
        Active
        Banned(reason is String)
        
    alias Balance = u256

Part 4: Authorities, Access Control, and Guards
Most smart contract hacks happen because of broken access control (e.g., anyone can call a function that should be admin-only).
Forge solves this by mandating an Explicit Authority System. There is no msg.sender == owner hidden inside code blocks. All power is declared upfront.
Declaring Power
In the authorities: block, you list out the roles that exist within your contract.
    authorities:
        // A single wallet, assigned on deployment
        admin is AdminAuth held_by Wallet initially deployer
        
        // A role that no one holds yet
        minter is MintAuth held_by Wallet initially nobody
        
        // A DAO / Program-controlled authority
        governance is GovAuth held_by Program initially known.DAO_Program

The only Statement
Inside your actions, you restrict execution using only. If the caller (the user signing the transaction) does not hold the exact authority, the invocation immediately panics.
    action emergency_pause():
        only admin
        // ... pause logic

You can also use complex only conditions natively recognized by the compiler:
    action dual_role_action():
        only admin or minter             // Either role can sign
        
    action specific_accounts():
        only [known.Alice, known.Bob]    // Hardcoded address list
        
    action multisig_any():
        only multisig_auth.any_signer    // Any member of a multisig

Advanced Authorities
Forge authorities have native advanced features:
 * Timelocks: Delay destructive actions natively without extra contracts.
   admin is Auth held_by Wallet with_timelock 2 days
 * Inheritance: Roles can automatically assume the powers of lesser roles.
   super_admin covers admin
Guards
Guards are composable, reusable access modifiers that can run complex checks before an action body executes.
    guard is_active_system:
        need mine.is_active else "System is paused"
        
    action deposit(amount is u256):
        guard is_active_system
        // Deposit logic runs here if the guard passes

Part 5: Control Flow, Actions, and Error Handling
Forge separates logic into distinct categories based on state mutation to aid in auditing and gas optimization.
Actions, Views, and Pures
 * action: Modifies state. Costs gas.
 * view: Reads state but cannot modify it. Usually free when called from a UI.
 * pure: Does not read or write state. Performs raw computation (e.g., math hashing).
    action update_name(new_name is String):
        mine.name = new_name
        
    view get_name() gives String:
        give back mine.name
        
    pure add_math(a is u256, b is u256) gives u256:
        give back a plus b

Conditionals (When/Otherwise)
Forge uses when and otherwise instead of if/else.
    when balance > 100:
        apply_discount()
    otherwise when balance > 50:
        apply_small_discount()
    otherwise:
        charge_full_price()

Pattern Matching (match)
Pattern matching is natively supported and highly recommended over massive when/otherwise chains.
    match user_status:
        Status.Banned(reason) -> throw BannedError(reason)
        Status.Active         -> proceed()
        _                     -> throw "Unknown status"

Loops (With Gas Protection)
Infinite loops are the enemy of blockchains. Forge protects against this by forcing loop annotations whenever you iterate over untrusted user input.
    // 'each' loop over a map
    each (user, amount) in mine.pending_payouts:
        pay user amount
    
    // Iterating over user parameters MUST have #[max_iterations]
    #[max_iterations 50]
    each addr in params.user_list:
        mine.approved[addr] = yes
        
    // 'repeat' loop
    repeat 3 times:
        mine.counter += 1
        
    // 'while' loop
    while mine.counter < 10:
        mine.counter += 1

Error Handling & Safety
Forge believes in failing early and failing safely to prevent corrupted state.
1. need and ensure
Instead of require, Forge uses need (pre-condition) and ensure (post-condition).
    need caller == mine.owner else "Not authorized"
    
    let old_bal = mine.balances[caller]
    mine.balances[caller] -= amount
    
    ensure mine.balances[caller] == old_bal minus amount else "Math error"

2. Typed Errors
You can throw explicitly typed errors which clients and other contracts can catch.
    error InsufficientFunds(available is u256, required is u256)
    
    action withdraw(amount is u256):
        need mine.balances[caller] >= amount else InsufficientFunds(mine.balances[caller], amount)

3. Attempt / On_Error (Try/Catch)
Catch errors from other contracts (or internally) without failing the whole transaction.
    attempt:
        known.Oracle.get_price()
    on_error OracleFailed(msg):
        use_fallback_price()
    always_after:
        log_attempt()

Part 6: Native Assets, Linear Types, and ZK Execution
Advanced developers require top-tier performance, deep economic integration, and sometimes absolute privacy. Forge incorporates these at the language level.
Native Assets & Linear Types
Unlike ERC-20 tokens, which are just numbers in a map, Forge treats assets as native logical resources (using the Linear Type algebraic theory). An asset created in memory must be stored, sent, or explicitly burned. If you forget to use an asset object, your contract will fail to compile.
    asset StableCoin:
        name: "Forge Dollar"
        symbol: "ZUSD"
        decimals: 6
        
        authorities:
            minter is MintAuth held_by Wallet initially deployer
            
        before_transfer:
            // This hook runs every time ZUSD moves anywhere on the network!
            need caller is_not known.Blacklist else "Banned Address"
            
    // Moving linear assets:
    action deposit(amount is u256):
        // Automatically checks if `caller` has `amount` of ZUSD
        let tokens = StableCoin.unwrap(amount)
        move tokens into mine.treasury

Keywords involved in native assets:
 * send asset to account
 * move asset into map_or_field
 * burn asset
 * split(), wrap(), merge()
Parallel Execution (#[parallel])
Forge can execute thousands of transactions in parallel if they don't touch the same exact account variables.
A simple token transfer modifies:
 * Alice's Balance
 * Bob's Balance
It does not modify a global "Treasury" state. Therefore, it can be run in parallel with millions of other transfers. You can instruct the compiler that you intend an action to run in parallel using the #[parallel] annotation. The checker.zig module will strictly verify that you are not reading or writing to globally shared state.
    #[parallel]
    action fast_transfer(receiver is Account, amount is u256):
        need mine.balances[caller] >= amount else "Insufficient"
        mine.balances[caller] -= amount
        mine.balances[receiver] += amount

Note: If fast_transfer accidentally modified mine.global_config, the compiler would throw the UndeclaredWrite error and refuse to build the contract.
ZK (Zero-Knowledge) & Privacy
Sometimes data needs to be verified without being revealed on-chain. Forge supports Zero-Knowledge proofs out of the box.
Using #[zk_proof], you offload execution to the client device. The blockchain only verifies the generated proof.
Using #[private], you specify which function arguments are never uploaded to the public blockchain database.
    #[zk_proof "zk/circuits/AgeVerification.json"]
    action verify_over_18(
        user_pubkey is PublicKey, 
        #[private] dob is Timestamp
    ):
        // The chain executes this via ZK-SNARK verification, blinding `dob`.
        let age = now() minus dob
        need age >= 18 years else "Underage"
        
        mine.is_verified[user_pubkey] = yes

Part 7: Walkthrough Tutorials
To bring it all together, let us look at two complete examples ranging from a simple beginner application to an advanced DeFi primitive.
Beginner Walkthrough: Tip Box
A simple contract that accepts native currency and lets the deployer withdraw it.
version 1

contract TipBox:
    has:
        total_tips is u256

    authorities:
        owner is OwnerAuth held_by Wallet initially deployer

    event Tipped(tipper is Account, amount is u256)

    setup():
        mine.total_tips = 0

    // Anyone can call this to tip
    action tip():
        need value > 0 else "Must attach ZPH to tip"
        
        mine.total_tips += value
        tell Tipped(caller, value)

    // Only the deployer can withdraw
    action withdraw_all():
        only owner
        let amount = mine.total_tips
        mine.total_tips = 0
        pay caller amount

Advanced Walkthrough: Secure Token Swap
A decentralized exchange (DEX) swap contract utilizing native asset transfers and protecting against reentrancy.
version 1

use std.math.percent

contract TokenSwap:
    accounts:
        price_oracle is Data global readonly
    
    has:
        fee_rate is Fixed[4]
        
    authorities:
        admin is AdminAuth held_by Wallet initially deployer

    setup():
        mine.fee_rate = 1_00.00 %  // 1% fee

    action update_fee(new_fee is Fixed[4]):
        only admin
        need new_fee <= 10_00.00 % else "Fee too high"
        mine.fee_rate = new_fee

    //#[reads price_oracle]
    action swap_usd_for_token(amount_in is u256):
        // 1. Unwrap the incoming native linear asset
        let usd = known.USDC.unwrap(amount_in)
        
        // 2. Fetch price from Oracle (read-only capability)
        let token_price = price_oracle.get_price("TKN")
        
        // 3. Math (safely managed by compiler)
        let fee = amount_in times mine.fee_rate
        let swap_amount = amount_in minus fee
        let tokens_out = swap_amount divided_by token_price
        
        // 4. Move assets
        move usd into known.Treasury
        
        // 5. Cross Contract Call: Deferred to prevent Reentrancy
        schedule known.TKN.mint(caller, tokens_out) after 0 seconds

Happy building on Forge! Remember: write code that reads like what it does.
