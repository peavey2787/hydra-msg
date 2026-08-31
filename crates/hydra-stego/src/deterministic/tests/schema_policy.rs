use super::*;

#[test]
fn deterministic_lexicon_stays_inside_the_technical_domain() {
    let forbidden = [
        "coffee",
        "lunch",
        "dinner",
        "weekend",
        "venue",
        "guestlist",
        "calendar",
        "trip",
        "favorite",
        "gonna",
        "wanna",
        "gotta",
        " the team ",
        " we ",
        " they ",
    ];
    let states = [
        ReportState::Planning,
        ReportState::Status,
        ReportState::Transfer,
        ReportState::Closing,
    ];
    let context = CoverContext::default();

    for state in states {
        for template in templates() {
            for variant in 0_u8..16 {
                let mut values = [variant; CHOICES_PER_SENTENCE - 1];
                for (value_index, value) in values.iter_mut().enumerate() {
                    if template.value_bits(&context, value_index) == 0 {
                        *value = 0;
                    }
                }
                let lower = format!(
                    " {} ",
                    template
                        .render(state, &context, &values)
                        .to_ascii_lowercase()
                );
                for term in forbidden {
                    assert!(
                        !lower.contains(term),
                        "nontechnical term {term:?} in: {lower}"
                    );
                }
            }
        }
    }
}

#[test]
fn all_templates_exclude_conversational_and_passive_chains() {
    let context = CoverContext::default();
    let values = [0_u8; CHOICES_PER_SENTENCE - 1];
    for template in templates() {
        let rendered = template.render(ReportState::Status, &context, &values);
        let lower = rendered.to_ascii_lowercase();
        for marker in [
            " currently ",
            " then ",
            " is expected to ",
            " is scheduled to ",
            " is configured to ",
            " is ready to ",
            " is queued to ",
            " continues to ",
            " remains queued to ",
            "could you",
            "would you",
            "please",
            "let me know",
            "so the record stays current",
            "before the day gets busy",
        ] {
            assert!(
                !lower.contains(marker),
                "forbidden phrasing {marker:?} in: {rendered}"
            );
        }
    }
}

#[test]
fn restriction_density_matches_schema_families() {
    let context = CoverContext::default();
    let without_restriction = templates()
        .iter()
        .filter(|template| template.value_bits(&context, Slot::Restriction.index()) == 0)
        .count();
    assert_eq!(without_restriction, 8);
    assert!(templates()
        .iter()
        .all(|template| template.value_bits(&context, Slot::Mode.index()) == 4));
    assert!(templates()
        .iter()
        .all(|template| template.value_bits(&context, Slot::Setting.index()) == 0));
}

#[test]
fn context_becomes_data_bearing_after_anchor() {
    let state = ReportState::Planning;
    let mut context = CoverContext::default();
    let values = [0_u8; CHOICES_PER_SENTENCE - 1];
    assert_eq!(
        templates()[0].value_bits(&context, Slot::Setting.index()),
        0
    );
    templates()[0].commit(state, &mut context, &values);
    assert_eq!(
        templates()[0].value_bits(&context, Slot::Setting.index()),
        4
    );
}

#[test]
fn each_event_family_has_four_template_symbols() {
    let counts = [
        EventFamily::Build,
        EventFamily::Metric,
        EventFamily::Deploy,
        EventFamily::Trace,
    ]
    .into_iter()
    .map(|family| {
        templates()
            .iter()
            .filter(|template| template.family() == family)
            .count()
    })
    .collect::<Vec<_>>();
    assert_eq!(counts, vec![4, 4, 4, 4]);
}

#[test]
fn control_pools_are_sixteen_way_and_varied() {
    for pool in [
        &BUILD_STATES,
        &METRIC_STATES,
        &DEPLOY_STATES,
        &TRACE_RESULTS,
    ] {
        assert_eq!(pool.len(), 16);
        assert_eq!(pool.iter().collect::<HashSet<_>>().len(), 16);
        assert!(pool
            .iter()
            .any(|value| value.split_whitespace().count() == 1));
        assert!(pool
            .iter()
            .any(|value| value.split_whitespace().count() > 1));
    }
}
