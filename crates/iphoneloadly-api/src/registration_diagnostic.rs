//! Counts identifier matches without exposing identifiers or changing registration policy.

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RegistrationMatches {
    pub listed_devices: usize,
    pub exact: usize,
    pub ascii_case_insensitive: usize,
    pub trimmed_ascii_case_insensitive: usize,
    pub target_has_outer_whitespace: bool,
}

pub(crate) fn registration_matches<'a>(
    target: &str,
    device_numbers: impl IntoIterator<Item = &'a str>,
) -> RegistrationMatches {
    let mut result = RegistrationMatches {
        target_has_outer_whitespace: target != target.trim(),
        ..RegistrationMatches::default()
    };
    for number in device_numbers {
        result.listed_devices += 1;
        result.exact += usize::from(number == target);
        result.ascii_case_insensitive += usize::from(number.eq_ignore_ascii_case(target));
        result.trimmed_ascii_case_insensitive +=
            usize::from(number.trim().eq_ignore_ascii_case(target.trim()));
    }
    result
}

/// Team IDs are public signing metadata. Reject unexpected payloads in logs.
pub(crate) fn diagnostic_team_id(team_id: &str) -> &str {
    if team_id.len() == 10 && team_id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        team_id
    } else {
        "<redacted-invalid-team-id>"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_exact_case_and_whitespace_matches() {
        let result = registration_matches(
            "00008110-ABCDEF0123456789",
            [
                "00008110-ABCDEF0123456789",
                "00008110-abcdef0123456789",
                " 00008110-abcdef0123456789\n",
                "00008110-1111111111111111",
            ],
        );
        assert_eq!(result.listed_devices, 4);
        assert_eq!(result.exact, 1);
        assert_eq!(result.ascii_case_insensitive, 2);
        assert_eq!(result.trimmed_ascii_case_insensitive, 3);
        assert!(!result.target_has_outer_whitespace);
    }

    #[test]
    fn detects_outer_whitespace_on_phone_identifier() {
        let result = registration_matches(" ABC123\n", ["abc123"]);
        assert_eq!(result.exact, 0);
        assert_eq!(result.ascii_case_insensitive, 0);
        assert_eq!(result.trimmed_ascii_case_insensitive, 1);
        assert!(result.target_has_outer_whitespace);
    }

    #[test]
    fn distinguishes_missing_identifier_and_empty_device_list() {
        let missing = registration_matches("ABC123", ["DEF456"]);
        assert_eq!(missing.listed_devices, 1);
        assert_eq!(missing.exact, 0);
        assert_eq!(missing.trimmed_ascii_case_insensitive, 0);
        assert_eq!(
            registration_matches("ABC123", []),
            RegistrationMatches::default()
        );
    }

    #[test]
    fn excludes_unexpected_team_payloads_from_logs() {
        assert_eq!(diagnostic_team_id("TEAMID1234"), "TEAMID1234");
        for invalid in [
            "",
            "TEAMID1234\n",
            "unexpected secret payload",
            "TEAMID123!",
        ] {
            assert_eq!(diagnostic_team_id(invalid), "<redacted-invalid-team-id>");
        }
    }
}
