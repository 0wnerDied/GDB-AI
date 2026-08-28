use gdb_ai_mi::{MiFramer, MiLimits, parse_record};

#[test]
fn parses_saved_transcripts_at_every_chunk_boundary() {
    for fixture in [
        include_bytes!("../../../tests/mi-fixtures/basic.mi").as_slice(),
        include_bytes!("../../../tests/mi-fixtures/future-fields.mi").as_slice(),
    ] {
        let expected = fixture
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| parse_record(line, MiLimits::default()).unwrap())
            .collect::<Vec<_>>();
        for chunk_size in 1..=fixture.len() {
            let mut framer = MiFramer::new(MiLimits::default());
            let mut actual = Vec::new();
            for chunk in fixture.chunks(chunk_size) {
                actual.extend(
                    framer
                        .push(chunk)
                        .unwrap()
                        .into_iter()
                        .map(|line| parse_record(&line, MiLimits::default()).unwrap()),
                );
            }
            assert_eq!(actual, expected, "chunk size {chunk_size}");
        }
    }
}
