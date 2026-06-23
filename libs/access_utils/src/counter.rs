use soroban_sdk::Env;

/// Reads a `u64` counter from persistent storage at `key`, increments it by 1,
/// writes the new value back, and returns the new count.
/// Returns `None` if the counter would overflow `u64::MAX`.
pub fn increment_counter<K>(env: &Env, key: &K) -> Option<u64>
where
    K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
{
    let current: u64 = env.storage().persistent().get(key).unwrap_or(0);
    let next = current.checked_add(1)?;
    env.storage().persistent().set(key, &next);
    Some(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, contracttype, Env};

    #[contracttype]
    #[derive(Clone)]
    pub enum TestKey {
        Counter,
        Other,
    }

    #[contract]
    struct CounterTestContract;

    #[contractimpl]
    impl CounterTestContract {
        pub fn inc(env: Env, key: TestKey) -> Option<u64> {
            increment_counter(&env, &key)
        }

        pub fn set(env: Env, key: TestKey, val: u64) {
            env.storage().persistent().set(&key, &val);
        }

        pub fn get(env: Env, key: TestKey) -> u64 {
            env.storage().persistent().get(&key).unwrap_or(0)
        }
    }

    fn setup() -> (Env, soroban_sdk::Address) {
        let env = Env::default();
        let id = env.register_contract(None, CounterTestContract);
        (env, id)
    }

    #[test]
    fn increment_from_zero() {
        let (env, id) = setup();
        let client = CounterTestContractClient::new(&env, &id);
        assert_eq!(client.inc(&TestKey::Counter), Some(1));
    }

    #[test]
    fn increment_sequential() {
        let (env, id) = setup();
        let client = CounterTestContractClient::new(&env, &id);
        assert_eq!(client.inc(&TestKey::Counter), Some(1));
        assert_eq!(client.inc(&TestKey::Counter), Some(2));
        assert_eq!(client.inc(&TestKey::Counter), Some(3));
    }

    #[test]
    fn increment_different_keys_are_independent() {
        let (env, id) = setup();
        let client = CounterTestContractClient::new(&env, &id);
        assert_eq!(client.inc(&TestKey::Counter), Some(1));
        assert_eq!(client.inc(&TestKey::Other), Some(1));
        assert_eq!(client.inc(&TestKey::Counter), Some(2));
        assert_eq!(client.inc(&TestKey::Other), Some(2));
    }

    #[test]
    fn overflow_returns_none() {
        let (env, id) = setup();
        let client = CounterTestContractClient::new(&env, &id);
        client.set(&TestKey::Counter, &u64::MAX);
        assert_eq!(client.inc(&TestKey::Counter), None);
    }

    #[test]
    fn overflow_does_not_mutate_storage() {
        let (env, id) = setup();
        let client = CounterTestContractClient::new(&env, &id);
        client.set(&TestKey::Counter, &u64::MAX);
        let _ = client.inc(&TestKey::Counter);
        assert_eq!(client.get(&TestKey::Counter), u64::MAX);
    }

    #[test]
    fn increment_near_max() {
        let (env, id) = setup();
        let client = CounterTestContractClient::new(&env, &id);
        client.set(&TestKey::Counter, &(u64::MAX - 1));
        assert_eq!(client.inc(&TestKey::Counter), Some(u64::MAX));
        assert_eq!(client.inc(&TestKey::Counter), None);
    }
}
