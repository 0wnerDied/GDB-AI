use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    session::{CommandReply, SessionHandle},
};

pub(super) async fn safe_evaluate_command(
    handle: &SessionHandle,
    command: MiCommand,
) -> Result<CommandReply> {
    handle.safe_evaluate(command).await
}

pub(super) fn validate_expression(expression: &str) -> Result<()> {
    if expression.is_empty() || expression.len() > 4_096 || expression.contains('\0') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "expression must contain 1 to 4096 bytes and no NUL",
        ));
    }

    // 2026-08-29: Legacy GDB cannot disable register writes after a live
    // inferior exists. Reject mutation and call syntax before GDB sees it;
    // backend guards still independently block inferior calls and memory.
    let bytes = expression.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            continue;
        }

        let next = bytes.get(index + 1).copied();
        if byte == b'/' && matches!(next, Some(b'/' | b'*')) {
            return unsafe_expression();
        }
        if matches!((byte, next), (b'+', Some(b'+')) | (b'-', Some(b'-'))) {
            return unsafe_expression();
        }
        if byte == b'=' {
            let previous = index.checked_sub(1).and_then(|i| bytes.get(i)).copied();
            let before_previous = index.checked_sub(2).and_then(|i| bytes.get(i)).copied();
            let comparison = next == Some(b'=')
                || matches!(previous, Some(b'=' | b'!'))
                || matches!(previous, Some(b'<' | b'>')) && before_previous != previous;
            if !comparison {
                return unsafe_expression();
            }
        }
        if byte == b'(' {
            let prefix = expression[..index].trim_end();
            let Some(previous) = prefix.as_bytes().last().copied() else {
                continue;
            };
            if matches!(previous, b')' | b']') {
                return unsafe_expression();
            }
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                let start = prefix
                    .rfind(|character: char| {
                        !(character.is_ascii_alphanumeric() || character == '_')
                    })
                    .map_or(0, |offset| offset + 1);
                if !matches!(
                    &prefix[start..],
                    "sizeof"
                        | "alignof"
                        | "_Alignof"
                        | "__alignof__"
                        | "typeof"
                        | "__typeof__"
                        | "decltype"
                ) {
                    return unsafe_expression();
                }
            }
        }
    }
    Ok(())
}

fn unsafe_expression() -> Result<()> {
    Err(Error::new(
        ErrorCode::PolicyDenied,
        "safe evaluation forbids calls and mutation operators",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_calls_and_mutations() {
        for expression in [
            "global_value",
            "&large_buffer",
            "$pc == 0",
            "(struct pair *)global",
            "sizeof(global_value)",
        ] {
            validate_expression(expression).unwrap();
        }
        for expression in [
            "global_value = 1",
            "++global_value",
            "$rax += 1",
            "marker()",
            "$_shell(\"id\")",
            "marker/**/()",
        ] {
            assert_eq!(
                validate_expression(expression).unwrap_err().code,
                ErrorCode::PolicyDenied,
                "accepted unsafe expression: {expression}"
            );
        }
    }
}
