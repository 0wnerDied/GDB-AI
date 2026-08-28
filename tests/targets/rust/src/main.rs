fn marker(value: &mut u64) {
    *value = 42;
}

fn main() {
    let mut value = 7;
    marker(&mut value);
    assert_eq!(value, 42);
}
