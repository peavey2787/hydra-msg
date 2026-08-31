use super::*;

#[test]
fn every_grammar_choice_round_trips_without_template_ambiguity() {
    let states = [
        ReportState::Planning,
        ReportState::Status,
        ReportState::Transfer,
        ReportState::Closing,
    ];
    for state in states {
        for (expected_template, template) in templates().iter().enumerate() {
            for variant in 0_u8..16 {
                let context = CoverContext::default();
                let mut values = [
                    variant,
                    variant.wrapping_mul(3) & 15,
                    variant.wrapping_mul(5) & 15,
                    variant.wrapping_mul(7) & 15,
                    variant.wrapping_mul(9) & 15,
                    variant.wrapping_mul(11) & 15,
                    variant.wrapping_mul(13) & 15,
                    variant.wrapping_mul(15) & 15,
                ];
                for (value_index, value) in values.iter_mut().enumerate() {
                    if template.value_bits(&context, value_index) == 0 {
                        *value = 0;
                    }
                }
                assert_eq!(values.len(), CHOICES_PER_SENTENCE - 1);
                let rendered = template.render(state, &context, &values);
                let observed = words(&rendered).collect::<Vec<_>>();
                let matches = templates()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, candidate)| {
                        candidate
                            .parse(&observed, 0, state, &context)
                            .map(|(end, decoded)| (index, end, decoded))
                    })
                    .collect::<Vec<_>>();
                assert_eq!(matches, vec![(expected_template, observed.len(), values)]);
            }
        }
    }
}

#[test]
fn four_event_families_use_distinct_stable_schema_shapes() {
    let context = CoverContext::default();
    let values = [0_u8; CHOICES_PER_SENTENCE - 1];
    let representatives = [0_usize, 4, 8, 12];
    let key_counts = representatives
        .iter()
        .map(|index| {
            templates()[*index]
                .render(ReportState::Planning, &context, &values)
                .split_whitespace()
                .filter(|token| token.contains('='))
                .count()
        })
        .collect::<HashSet<_>>();
    assert_eq!(key_counts, HashSet::from([6, 8, 9, 11]));

    let build = templates()[0].render(ReportState::Planning, &context, &values);
    assert_key_order(
        &build,
        &[
            "ts=", "status=", "event=", "actor=", "action=", "target=", "mode=", "context=",
            "detail=",
        ],
    );
    let metric = templates()[4].render(ReportState::Planning, &context, &values);
    assert_key_order(
        &metric,
        &["ts=", "metric=", "source=", "state=", "op=", "value="],
    );
    let deploy = templates()[8].render(ReportState::Planning, &context, &values);
    assert_key_order(
        &deploy,
        &[
            "ts=", "event=", "target=", "status=", "actor=", "context=", "action=", "mode=",
        ],
    );
    let trace = templates()[12].render(ReportState::Planning, &context, &values);
    assert_key_order(
        &trace,
        &[
            "ts=",
            "severity=",
            "event=",
            "component=",
            "result=",
            "actor=",
            "target=",
            "action=",
            "mode=",
            "detail=",
            "retry=",
        ],
    );
}

#[test]
fn schema_varies_by_family_not_random_delimiter_style() {
    let context = CoverContext::default();
    let values = [0_u8; CHOICES_PER_SENTENCE - 1];
    for (index, template) in templates().iter().enumerate() {
        let rendered = template.render(ReportState::Planning, &context, &values);
        assert!(rendered.starts_with("ts="));
        assert!(!rendered.contains(" | "));
        assert!(!rendered.contains("::"));
        assert!(!rendered.contains('\n'));
        match index / 4 {
            0 => assert!(rendered.contains(" status=\"") && rendered.contains(" detail=\"")),
            1 => assert!(
                rendered.contains(" metric=\"")
                    && rendered.contains(" op=\"")
                    && rendered.contains(" value=")
            ),
            2 => assert!(rendered.contains(" event=") && !rendered.contains(" detail=")),
            3 => assert!(rendered.contains(" severity=") && rendered.contains(" retry=")),
            _ => unreachable!(),
        }
    }
}

#[test]
fn family_correlates_actor_context_action_and_target_domain() {
    let context = CoverContext::default();
    let mut values = [0_u8; CHOICES_PER_SENTENCE - 1];
    values[Slot::Verb.index()] = 0;

    let build = templates()[0].render(ReportState::Planning, &context, &values);
    assert!(build.contains("actor=\"runner\""));
    assert!(build.contains("action=\"queue\""));
    assert!(build.contains("context=\"build runner"));
    assert!(build.contains("target=\"current PR"));

    let metric = templates()[4].render(ReportState::Planning, &context, &values);
    assert!(metric.contains("source=\"exporter metrics endpoint"));
    assert!(metric.contains(" state=\"NOMINAL\""));
    assert!(metric.contains(" op=\"atomic sample\""));
    assert!(metric.contains("metric=\"gauge service latency\""));

    let deploy = templates()[8].render(ReportState::Planning, &context, &values);
    assert!(deploy.contains("actor=\"controller\""));
    assert!(deploy.contains("context=\"deploy controller"));
    assert!(deploy.contains("action=\"stage\""));
    assert!(deploy.contains("target=\"primary service"));

    let trace = templates()[12].render(ReportState::Planning, &context, &values);
    assert!(trace.contains("actor=\"checker\""));
    assert!(trace.contains("component=\"validation worker"));
    assert!(trace.contains("action=\"inspect\""));
    assert!(trace.contains("target=\"current check"));
}

#[test]
fn continuation_actor_bit_stays_inside_each_family() {
    let state = ReportState::Planning;
    let mut context = CoverContext::default();
    let mut values = [0_u8; CHOICES_PER_SENTENCE - 1];
    templates()[0].commit(state, &mut context, &values);
    values[Slot::Subject.index()] = 1;

    assert!(templates()[0]
        .render(state, &context, &values)
        .contains("actor=\"builder\""));
    assert!(templates()[4]
        .render(state, &context, &values)
        .contains("source=\"monitor "));
    assert!(templates()[8]
        .render(state, &context, &values)
        .contains("actor=\"deployer\""));
    assert!(templates()[12]
        .render(state, &context, &values)
        .contains("actor=\"agent\""));
}

#[test]
fn first_record_locks_one_machine_register_for_the_message() {
    let state = ReportState::Planning;
    let mut context = CoverContext::default();
    let mut values = [0_u8; CHOICES_PER_SENTENCE - 1];
    values[Slot::Control.index()] = 0;
    templates()[0].commit(state, &mut context, &values);
    templates()[0].commit(state, &mut context, &values);

    values[Slot::Control.index()] = 15;
    values[Slot::Mode.index()] = 0;
    let continued = templates()[0].render(state, &context, &values);
    assert!(continued.contains("mode=\"atomic\""));
    assert!(!continued.contains("mode=\"direct\""));
}
