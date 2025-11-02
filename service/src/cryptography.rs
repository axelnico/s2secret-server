use rand::distr::Alphanumeric;
use rand::Rng;

pub fn one_time_secret_code() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}