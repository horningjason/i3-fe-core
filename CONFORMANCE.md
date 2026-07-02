# Conformance matrix — NENA-STA-010.3f-2021

This file is updated as each module is implemented. One row per normative
requirement. "How verified" must reference either a unit/integration test
(module::test_name) or a runtime check visible in the conformance test suite.

## Standard coverage

| Standard section | Topic | Status |
|---|---|---|
| §2.1 | Agency / Agent / Element identifiers (FQDN, Dot-string) | Implemented — `config.identity` |
| §2.2 | NTP (RFC 5905), ≤ 0.1 s drift budget | Implemented — `time.ntp` |
| §2.3 | i3 Timestamp (RFC 3339 with explicit offset, sub-second) | Implemented — `time.timestamps` |
| §2.4.1 | ElementState event package (RFC 6665 + RFC 6446) | Implemented — `state.element_state`, `notify.sip_notifier` |
| §2.4.2 | ServiceState event package (RFC 6665 + RFC 6446) | Implemented — `state.service_state`, `notify.sip_notifier` |
| §3.7, §3.7.1–3.7.3 | Discrepancy Reporting web service (generic DR function) | Implemented — `discrepancy.models`, `discrepancy.service`, `discrepancy.routes` |
| §2.8.1 | HTTPS, TLS 1.2 minimum, MUST NOT offer TLS 1.0/1.1, PFS | Implemented — `security.tls` |
| §4.12.3.1 | LogEvent prologue (12 fields, camelCase, JWS signing) | Implemented — `logging.logevent`, `logging.logging_client`, `logging.jws_signer` |
| §4.12.3.1.2 | POST LogEvents to Logging Service | Implemented — `logging.logging_client` |
| §5.10 | JWS Flat JSON, EdDSA/Ed448, x5c / x5u+x5t#S256 cert delivery | Implemented — `logging.jws_signer` |
| §3.7.22 | Log Signature/Certificate Discrepancy Report (8 problem tokens) | Implemented — `logging.jws_signer` |
| §10.12 | serviceState IANA registry (10 values) | Implemented — `state.store`, `state.service_state` |
| §10.13 | elementState IANA registry (7 values) | Implemented — `state.store`, `state.element_state` |
| §10.18 | securityPosture IANA registry (4 values) | Implemented — `state.store`, `state.service_state` |
| Conformance suite | Reusable pytest helpers + `assert_core_conformance` | Implemented — `conformance.checks` |

**Not yet implemented** (out of scope for i3-fe-core cross-cutting layer):
- §3.x Call handling (SIP dialogs, INVITEs, call routing) — each FE's own concern
- §3.7.4–§3.7.21 type-specific DR parameter validation — the generic §3.7.1–3.7.3
  web service is implemented (see coverage row above) and carries
  reportType-dependent parameters opaquely in the top-level JSON object as the
  standard requires; validating each type's parameter block (e.g. the LoST
  `query`/`request`/`response`/`problem` fields, §3.7.5) is the owning FE's
  concern.  §3.7.22 (Log Signature/Certificate DR) has typed support in
  `logging.jws_signer`.
- §4.x FE-specific service interfaces (LVF/ECRF LoST §4.3, MCS `PIDFLOtoMSAG`/
  `MSAGtoPIDFLO` §4.4, GCS `Geocode`/`ReverseGeocode` §4.5, MDS WFS/WMS §4.19, etc.)
- §4.12.3.1.1 Retrieve LogEvents (Logging Service read path)
- §5.x Security credential management (PCA, certificate lifecycle)
- §6.x–§9.x Routing, queuing, bridging, recording

| Requirement | Standard section | Module | How verified |
|---|---|---|---|
| Agency Identifier MUST be a globally-unique FQDN (RFC 2664) | §2.1.1 | `config.identity` | `test_identity::test_minimal_valid`, `test_fqdn_case_normalised`, `test_single_label_rejected` |
| Trailing dot in FQDN MUST be treated as equivalent to no trailing dot | §2.1.1 | `config.identity` | `test_identity::test_trailing_dot_normalised` |
| FQDNs are case-insensitive; normalised to lowercase | §2.1.1 | `config.identity` | `test_identity::test_fqdn_case_normalised` |
| Agent Identifier MUST use RFC 5321 Dot-string syntax | §2.1.2 | `config.identity` | `test_identity::test_agent_id_dot_string_valid`, `test_agent_id_with_space_rejected` |
| Element Identifier MUST be a globally-unique FQDN | §2.1.3 | `config.identity` | `test_identity::test_minimal_valid`, `test_empty_element_id_rejected` |
| Every element MUST implement NTP (RFC 5905) | §2.2 | `time.ntp` | `test_ntp::test_start_populates_sample`, `test_falls_back_to_second_server` |
| Absolute time difference between elements MUST be ≤ 0.1 s | §2.2 | `time.ntp` | `test_ntp::test_drift_threshold_is_point_one`, `test_is_healthy_within_threshold`, `test_is_unhealthy_outside_threshold` |
| Hardware clock hook MUST be available | §2.2 | `time.ntp` | `test_ntp::test_hardware_clock_hook_accepted` |
| Timestamps SHALL use RFC 3339 date-time format | §2.3 | `time.timestamps` | `test_timestamps::test_format_matches_standard_example_shape`, `test_round_trip` |
| Timestamp offset is REQUIRED (never bare Z) | §2.3 | `time.timestamps` | `test_timestamps::test_format_always_has_explicit_offset`, `test_format_utc_datetime_emits_plus_zero` |
| Offset MUST be based on creator's local time | §2.3 | `time.timestamps` | `test_timestamps::test_format_specific_offset` |
| Sub-second precision MUST be included when ordering matters | §2.3 | `time.timestamps` | `test_timestamps::test_sub_second_included_when_present`, `test_trailing_zeros_stripped` |
| ElementState NOTIFY body: elementId (MANDATORY), state (MANDATORY), reason (OPTIONAL) | §2.4.1 | `state.element_state` | `test_element_state::test_notify_body_mandatory_fields_present`, `test_notify_body_reason_omitted_when_empty`, `test_notify_body_reason_included_when_set` |
| elementId in NOTIFY body MUST come from injected identity, not env | §2.4.1 | `state.element_state` | `test_element_state::test_notify_body_element_id_from_identity` |
| state field MUST use exact §10.13 registry string value | §2.4.1, §10.13 | `state.element_state` | `test_element_state::test_element_state_registry_exact`, `test_element_state_count`, `test_notify_body_state_is_string_value` |
| §10.13 registry has exactly 7 values: Normal / ScheduledMaintenance / ServiceDisruption / Overloaded / GoingDown / Down / Unreachable | §10.13 | `state.element_state` | `test_element_state::test_element_state_registry_exact` |
| Event package name MUST be emergency-ElementState | §2.4.1 | `state.element_state` | `test_element_state::test_event_package_name` |
| NOTIFY MIME type MUST be Application/EmergencyCallData.ElementState+json | §2.4.1 | `state.element_state` | `test_element_state::test_notify_mime_type` |
| Notifiers MUST implement RFC 6446 event rate filters | §2.4.1 | `state.element_state` | `test_element_state::test_rate_limit_coalesces_rapid_changes`, `test_rate_limit_no_double_timer`, `test_rate_limit_falls_back_to_immediate_without_loop` |
| ElementState default at startup: state=Normal, reason="" | §2.4.1 | `state.store` | `test_store::test_element_state_default` |
| ServiceState NOTIFY body: service, name, domain (MANDATORY); serviceId (OPTIONAL = domain); serviceState{state,reason} (MANDATORY); securityPosture (CONDITIONAL) | §2.4.2 | `state.service_state` | `test_service_state::test_notify_body_service_mandatory`, `test_notify_body_name_mandatory`, `test_notify_body_domain_mandatory`, `test_notify_body_service_state_mandatory` |
| §10.12 registry has exactly 10 values: Normal/Unstaffed/ScheduledMaintenanceDown/ScheduledMaintenanceAvailable/MajorIncidentInProgress/Partial/Overloaded/GoingDown/Down/Unreachable | §10.12 | `state.service_state` | `test_service_state::test_service_state_registry_exact`, `test_service_state_count` |
| §10.18 registry has exactly 4 values: Green/Yellow/Orange/Red | §10.18 | `state.service_state` | `test_service_state::test_security_posture_registry_exact`, `test_security_posture_count` |
| Event package name MUST be emergency-ServiceState | §2.4.2 | `state.service_state` | `test_service_state::test_event_package_name` |
| NOTIFY MIME type MUST be Application/EmergencyCallData.ServiceState+json | §2.4.2 | `state.service_state` | `test_service_state::test_notify_mime_type` |
| name (IANA token) and service (subscribed URI) are DISTINCT fields | §2.4.2 | `state.service_state` | `test_service_state::test_notify_body_name_distinct_from_service` |
| serviceId if present MUST equal domain (§2.4.2 fn.4 compat note) | §2.4.2 | `state.service_state` | `test_service_state::test_service_id_present_when_provided`, `test_service_id_must_equal_domain` |
| serviceState.reason MUST be empty string (not absent/null) when no reason available | §2.4.2 | `state.service_state` | `test_service_state::test_notify_body_reason_is_always_string_not_none`, `test_notify_body_service_state_defaults` |
| securityPosture MUST be absent (not null) when service does not maintain posture | §2.4.2 | `state.service_state` | `test_service_state::test_security_posture_absent_when_not_supported` |
| securityPosture MUST be present when service opts in; defaults to Green | §2.4.2, §10.18 | `state.service_state` | `test_service_state::test_security_posture_present_when_opted_in`, `test_security_posture_default_green_when_no_posture_set` |
| securityPosture.posture MANDATORY when securityPosture present; reason OPTIONAL | §2.4.2 | `state.service_state` | `test_service_state::test_security_posture_posture_field_mandatory`, `test_security_posture_reason_omitted_when_empty` |
| Notifiers MUST implement RFC 6446 event rate filters | §2.4.2 | `state.service_state` | `test_service_state::test_rate_limit_coalesces_rapid_changes`, `test_rate_limit_falls_back_without_loop` |
| ServiceState is SERVICE-level; driven by external aggregator, not per-node element state | §2.4.2, §4.3.2.7 | `state.service_state` | `test_service_state::test_aggregate_set_state_drives_notifier` |
| ServiceState default at startup: state=Normal, reason="" | §2.4.2 | `state.store` | `test_store::test_service_state_default` |
| StateStore provides atomic get/set so shared backend can be substituted | §2.4 design | `state.store` | `test_store::test_is_state_store_subclass`, `test_element_and_service_stores_are_independent` |
| State transport shall use RFC 6665 SIP event framework | §2.4 | `notify.sip_notifier` | `test_sip_notifier::test_subscribe_element_triggers_initial_notify_with_correct_mime`, `test_subscribe_service_triggers_initial_notify_with_correct_mime` |
| SUBSCRIBE accepted for both emergency-ElementState and emergency-ServiceState | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_element_event_package_accepted`, `test_service_event_package_accepted` |
| Unknown event package MUST return 489 Bad Event | §2.4 (RFC 6665) | `notify.sip_notifier` | `test_sip_notifier::test_unknown_event_package_returns_489` |
| Subscription duration: default 1 hour, minimum 1 minute, maximum 24 hours | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_default_duration_when_expires_absent`, `test_expires_below_minimum_returns_400`, `test_expires_above_maximum_is_clamped` |
| Expires < 1 minute MUST be rejected (400) | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_expires_below_minimum_returns_400`, `test_expires_exactly_minimum_accepted` |
| Expires = 0 MUST remove the subscription | §2.4 (RFC 6665) | `notify.sip_notifier` | `test_sip_notifier::test_expires_zero_unsubscribes` |
| Initial NOTIFY MUST be sent immediately on successful SUBSCRIBE | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_subscribe_element_triggers_initial_notify_with_correct_mime`, `test_subscribe_service_triggers_initial_notify_with_correct_mime` |
| Initial NOTIFY body MUST carry correct MIME type and fields | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_subscribe_element_initial_notify_body_structure`, `test_subscribe_service_initial_notify_body_structure` |
| State changes MUST fan out NOTIFY to all matching active subscriptions | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_element_state_change_delivers_notify`, `test_service_state_change_delivers_notify`, `test_multiple_subscribers_all_receive_notify` |
| NOTIFY MUST NOT cross event packages (Element ↛ Service subscribers and vice versa) | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_element_change_does_not_fan_out_to_service_subscribers`, `test_service_change_does_not_fan_out_to_element_subscribers` |
| Notifier MUST implement RFC 6446 per-subscription minimum notification interval | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_rate_limited_subscription_coalesces_rapid_changes`, `test_service_rate_limited_subscription_coalesces` |
| Minimum interval filter doubles as a watchdog: NOTIFYs sent even without state change | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_rate_limited_watchdog_fires_even_without_state_change` |
| Forking MUST NOT be used (one Contact per subscription) | §2.4.1, §2.4.2 | `notify.sip_notifier` | Structural: each SipSubscription holds exactly one subscriber_uri |
| SIP listener is a process singleton; start only when WorkerContext.is_leader() | §2.4.1, §2.4.2 | `notify.sip_notifier` | `test_sip_notifier::test_start_returns_true_for_single_worker`, `test_start_returns_false_for_non_leader` |
| mTLS downgrade risk under gunicorn+UvicornWorker documented | §2.8 | `notify.sip_notifier` | Module docstring — ENVIRONMENT CAVEAT section |
| LogEvent prologue MUST contain logEventType (MANDATORY) | §4.12.3.1 | `logging.logevent` | `test_logevent::test_mandatory_fields_present`, `test_log_event_type_value` |
| LogEvent prologue MUST contain timestamp — i3 Timestamp per §2.3 | §4.12.3.1 | `logging.logevent` | `test_logevent::test_mandatory_fields_present`, `test_timestamp_is_string`, `test_timestamp_has_offset` |
| LogEvent prologue MUST contain elementId (§2.1.3 FQDN) | §4.12.3.1 | `logging.logevent`, `logging.logging_client` | `test_logevent::test_element_id_value`, `test_logging_client::test_emit_sets_element_id_from_identity` |
| LogEvent prologue MUST contain agencyId (§2.1.1 FQDN) | §4.12.3.1 | `logging.logevent`, `logging.logging_client` | `test_logevent::test_agency_id_value`, `test_logging_client::test_emit_sets_agency_id_from_identity` |
| elementId and agencyId MUST come from injected identity, not env | §4.12.3.1, §2.1 | `logging.logging_client` | `test_logging_client::test_emit_sets_element_id_from_identity`, `test_emit_overrides_caller_supplied_element_id` |
| CONDITIONAL prologue fields MUST be absent (not null) when condition not met | §4.12.3.1 | `logging.logevent` | `test_logevent::test_absent_conditional_fields_omitted`, `test_logevent::test_absent_optional_fields_omitted` |
| agencyAgentId CONDITIONAL — included only when traceable to an agent | §4.12.3.1 | `logging.logevent` | `test_logevent::test_absent_conditional_fields_omitted`, `test_agency_agent_id_included_when_set` |
| callId CONDITIONAL — required when event is associated with a call | §4.12.3.1 | `logging.logevent` | `test_logevent::test_call_id_included_when_set`, `test_absent_conditional_fields_omitted` |
| incidentId CONDITIONAL — required when event is associated with an incident | §4.12.3.1 | `logging.logevent` | `test_logevent::test_incident_id_included_when_set`, `test_absent_conditional_fields_omitted` |
| callIdSIP CONDITIONAL — must appear as "callIdSIP" (SIP all-caps) | §4.12.3.1 | `logging.logevent` | `test_logevent::test_sip_abbreviation_is_uppercase`, `test_call_id_sip_included_as_callIdSIP` |
| ipAddressPort CONDITIONAL — required when peer element identity is known | §4.12.3.1 | `logging.logevent` | `test_logevent::test_ip_address_port_included_when_set`, `test_absent_conditional_fields_omitted` |
| extension OPTIONAL 0+ — absent (not []) when no extensions provided | §4.12.3.1 | `logging.logevent` | `test_logevent::test_empty_extension_omitted`, `test_extension_included_when_non_empty` |
| JSON keys MUST be camelCase matching §4.12.3.1 field names exactly | §4.12.3.1 | `logging.logevent` | `test_logevent::test_to_i3_json_key_mapping` (12 parametrised cases) |
| Empty agencyId MUST produce a warning but event is still emitted | §4.12.3.1 | `logging.logging_client` | `test_logging_client::test_empty_agency_id_emits_warning`, `test_empty_agency_id_still_emits` |
| LogEvents MUST be emitted to stdlib logging always | §4.12.3.1 | `logging.logging_client` | `test_logging_client::test_emit_logs_to_stdlib_logging` |
| LogEvents MUST be POSTed to Logging Service when uri configured | §4.12.3.1.2 | `logging.logging_client` | `test_logging_client::test_http_post_when_uri_configured`, `test_http_post_url_contains_log_events_path` |
| POST endpoint is .../LogEvents; body is JSON unless signed | §4.12.3.1.2 | `logging.logging_client` | `test_logging_client::test_http_post_content_is_valid_json`, `test_http_post_content_type_json_without_signing` |
| JWS signing hook available — sign_payload callable wraps body; Content-Type: application/jose | §4.12.3.1, §5.10 | `logging.logging_client` | `test_logging_client::test_sign_payload_hook_called_when_provided`, `test_sign_payload_hook_content_type_is_jose`, `test_sign_payload_hook_posts_signed_bytes` |
| i3 services MUST support HTTPS; MUST support TLS 1.2 | §2.8.1 | `security.tls` | `test_tls::test_server_context_minimum_version_is_tls12`, `test_client_context_minimum_version_is_tls12` |
| MUST NOT offer or accept TLS 1.0 or TLS 1.1 | §2.8.1 | `security.tls` | `test_tls::test_server_context_no_tls10`, `test_server_context_no_tls11`, `test_client_context_no_tls10`, `test_client_context_no_tls11` |
| Perfect forward secrecy MUST be used within ESInet | §2.8.1 | `security.tls` | `test_tls::test_pfs_ciphers_constant_includes_ecdhe`, `test_pfs_ciphers_constant_includes_dhe`; cipher string selects ECDHE+DHE, excludes static RSA |
| mTLS must present client cert for outbound calls to peer FEs | §2.8 | `security.tls` | `make_client_ssl_context` loads cert+key in MTLS mode; `make_server_ssl_context` sets CERT_REQUIRED |
| gunicorn+UvicornWorker mTLS caveat: CERT_REQUIRED unreliable; use CERT_OPTIONAL + compensating control | §2.8 | `security.tls` | `test_tls::test_server_mtls_gunicorn_mode_uses_cert_optional`; warning logged |
| Mutual authentication MUST use a PCA-traceable certificate; proxy-terminated mTLS verified at app layer (403 on missing/expired/untraceable cert; /health exempt; header honored only from trusted proxies) | §5.4 | `security.peer_auth`, `app.factory` | `test_peer_auth::test_valid_pca_cert_header_gets_200_and_identity_on_scope`, `test_missing_cert_header_rejected_403`, `test_expired_cert_rejected_403`, `test_untraceable_cert_rejected_403`, `test_header_from_untrusted_source_rejected`, `test_health_stays_open_without_cert` |
| SIP SUBSCRIBE subscriber authorization + Contact-URI validation hooks (§5.4 mutual auth fed by wire layer); one-time warning when unconfigured | §5.4, §2.4 | `notify.sip_notifier` | `test_sip_notifier::test_unauthorized_subscriber_gets_403_and_nothing_stored`, `test_invalid_target_uri_gets_403_and_no_notify`, `test_no_hooks_logs_one_time_warning_and_behavior_unchanged` |
| NTP client poller is a process singleton; start only on leader worker | §2.2 | `app.lifecycle` | `test_lifecycle::test_non_leader_does_not_call_ntp_start` |
| SIP NOTIFY listener is a process singleton; start only on leader worker | §2.4 | `app.lifecycle` | `app.lifecycle.make_lifespan` — `sip_notifier.start()` behind `is_leader()` gate |
| ElementState initialised to Normal on startup; ServiceDisruption on hook failure | §2.4.1 | `app.lifecycle` | `test_lifecycle::test_startup_sets_element_state_normal`, `test_startup_hook_failure_sets_service_disruption` |
| ElementState set to GoingDown on graceful shutdown | §2.4.1 | `app.lifecycle` | `test_lifecycle::test_shutdown_sets_going_down` |
| NTP health monitor flips ElementState → ServiceDisruption when drift exceeds §2.2 budget | §2.2 | `app.lifecycle` | `test_lifecycle::test_ntp_health_loop_sets_service_disruption_when_unhealthy` |
| GET /health liveness probe present on every FE | §2.8 design | `app.factory` | `test_factory::test_health_returns_200_when_element_is_normal`, `test_health_returns_503_when_ntp_unhealthy` |
| GET /ElementState read-only status endpoint | §2.4.1 | `app.factory` | `test_factory::test_element_state_endpoint_body_has_mandatory_fields`, `test_element_state_endpoint_reflects_state_change` |
| GET /ServiceState read-only status endpoint | §2.4.2 | `app.factory` | `test_factory::test_service_state_endpoint_body_has_mandatory_fields`, `test_service_state_endpoint_reflects_state_change` |
| FE-specific routes added via register_routes callback without shadowing common endpoints | §2.8 design | `app.factory` | `test_factory::test_register_routes_callback_adds_custom_endpoint`, `test_register_routes_does_not_shadow_common_endpoints` |
| Request logging middleware emits one LogEvent per HTTP request | §4.12.3.1 | `app.factory` | `test_factory::test_middleware_emits_log_event_per_request`, `test_middleware_log_event_has_access_log_type`, `test_middleware_emits_log_event_for_each_request` |
| Middleware failure MUST NOT propagate to the HTTP response | §4.12.3.1 | `app.factory` | `test_factory::test_middleware_does_not_fail_on_emit_error` |
| Conformance helper `assert_element_state_registry()` verifies §10.13 exact 7-value set | §10.13 | `conformance.checks` | `test_conformance_suite::test_element_state_registry_exact_seven_values` |
| Conformance helper `assert_service_state_registry()` verifies §10.12 exact 10-value set | §10.12 | `conformance.checks` | `test_conformance_suite::test_service_state_registry_exact_ten_values` |
| Conformance helper `assert_security_posture_registry()` verifies §10.18 exact 4-value set | §10.18 | `conformance.checks` | `test_conformance_suite::test_security_posture_registry_exact_four_values` |
| Conformance helper `assert_timestamp_has_offset()` rejects bare Z; requires ±HH:MM | §2.3 | `conformance.checks` | `test_conformance_suite::test_timestamp_bare_z_fails`, `test_timestamp_no_offset_fails`, `test_timestamp_with_positive_offset_passes` |
| Conformance helper `assert_element_state_notify_body()` enforces §2.4.1 body structure | §2.4.1 | `conformance.checks` | `test_conformance_suite::test_element_state_body_*` (6 cases) |
| Conformance helper `assert_service_state_notify_body()` enforces §2.4.2 body structure including serviceId==domain and securityPosture constraints | §2.4.2 | `conformance.checks` | `test_conformance_suite::test_service_state_body_*` (8 cases) |
| Conformance helper `assert_log_event_prologue()` enforces §4.12.3.1 mandatory fields and conditional-absent-not-null rule | §4.12.3.1 | `conformance.checks` | `test_conformance_suite::test_log_event_prologue_*` (5 cases) |
| Conformance helper `assert_ntp_reporting()` verifies NTP client is present and exposes is_healthy | §2.2 | `conformance.checks` | `test_conformance_suite::test_ntp_reporting_*` (3 cases) |
| `assert_core_conformance(fe_app, identity)` passes for a correctly-wired FE and fails if elementId does not match identity | §2.4.1, §2.4.2, §2.2, §10.12, §10.13, §10.18 | `conformance.checks` | `test_conformance_suite::test_assert_core_conformance_passes_for_minimal_fe`, `test_assert_core_conformance_passes_with_security_posture_enabled`, `test_assert_core_conformance_wrong_identity_fails` |
| LogEvents stored as JWS per §4.12.3.1; JWS MUST use Flat JSON Serialization | §4.12.3.1, §5.10 | `logging.jws_signer` | `test_jws_signer::test_sign_flat_jws_has_payload_protected_signature`, `test_sign_no_extra_top_level_fields` |
| JWS algorithm MUST be "EdDSA" (Edwards-curve with Curve448/Ed448) | §5.10 | `logging.jws_signer` | `test_jws_signer::test_sign_alg_is_eddsa` |
| JWS Protected Header MUST specify signing cert by value (x5c) or by reference (x5u + x5t#S256) | §5.10 | `logging.jws_signer` | `test_jws_signer::test_sign_by_value_has_x5c`, `test_sign_by_ref_has_x5u_and_thumbprint` |
| x5c values are base64-encoded DER (leaf first, all intermediates included) | §5.10 | `logging.jws_signer` | `test_jws_signer::test_sign_by_value_x5c_is_base64_der`, `test_sign_cert_chain_all_certs_included` |
| x5t#S256 MUST be SHA-256 of the leaf cert's DER encoding, base64url-encoded | §5.10 | `logging.jws_signer` | `test_jws_signer::test_sign_by_ref_thumbprint_matches_leaf_cert` |
| x5u MUST be accompanied by x5t#S256 (thumbprint for cert integrity) | §5.10 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_by_ref_missing_thumbprint_returns_bad_thumb` |
| Unsigned JWS (alg=none) accepted ONLY when policy explicitly allows it (`allow_unsigned=True`); rejected by default to prevent signature stripping | §5.10 | `logging.jws_signer` | `test_jws_signer::test_verify_unsigned_jws_passes_when_policy_allows`, `test_verify_unsigned_jws_rejected_by_default`, `test_verify_signed_jws_downgraded_to_none_is_rejected` |
| x5c chain anchored to caller-supplied trust anchors; forged signer certs rejected (BadCertX5c) | §5.10 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_x5c_forged_cert_rejected_with_trust_anchors`, `test_verify_jws_x5c_anchored_to_trusted_cert_succeeds` |
| Signature verification: tampered payload or header MUST be detected | §4.12.3.1, §5.10 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_tampered_payload_returns_bad_signature`, `test_verify_jws_tampered_protected_header_returns_bad_signature` |
| Log Signature/Certificate Discrepancy Report (§3.7.22): 8 problem tokens, mandatory logEventId | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_discrepancy_problems_set_covers_all_standard_tokens`, `test_discrepancy_report_to_dict_mandatory_fields` |
| §3.7.22: BadAlgorithm reported when alg ≠ EdDSA | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_wrong_algorithm_returns_bad_algorithm` |
| §3.7.22: NoCert reported when neither x5c nor x5u present | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_no_cert_fields_returns_no_cert` |
| §3.7.22: BadURL reported when x5u cannot be resolved (result field REQUIRED) | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_by_ref_without_trusted_certs_returns_bad_url` |
| §3.7.22: BadThumb reported when x5t#S256 absent or does not match cert (thumbCalc REQUIRED) | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_bad_thumbprint_returns_bad_thumb`, `test_verify_jws_by_ref_missing_thumbprint_returns_bad_thumb` |
| §3.7.22: BadCertX5c reported for invalid certificate in x5c field | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_bad_x5c_cert_returns_bad_cert_x5c` |
| §3.7.22: BadSignature reported when signature does not verify | §3.7.22 | `logging.jws_signer` | `test_jws_signer::test_verify_jws_tampered_payload_returns_bad_signature` |
| LoggingClient posts Content-Type: application/jose when JwsSigner is wired | §4.12.3.1, §5.10 | `logging.jws_signer`, `logging.logging_client` | `test_jws_signer::test_logging_client_posts_application_jose_when_signer_wired` |
| Posted JWS verifies against signing cert and contains all mandatory prologue fields | §4.12.3.1 | `logging.jws_signer`, `logging.logging_client` | `test_jws_signer::test_logging_client_posted_jws_verifies_correctly`, `test_logging_client_jws_payload_contains_all_mandatory_prologue_fields` |
| FEs MUST support the DR function; DR web service mounted by default on every FE (POST/GET Reports, Resolutions, StatusUpdates) | §3.7, §3.7.1–3.7.3 | `discrepancy.routes`, `app.factory` | `test_dr_routes::test_dr_routes_mounted_by_default`, `test_post_reports_valid_returns_201`, `test_full_report_lifecycle_over_http` |
| DR prolog MANDATORY fields enforced (resolutionUri, reportType, submittal timestamp, reportId, reportingAgencyName, reportingContactJcard, problemSeverity); missing → 454 | §3.7.1 | `discrepancy.models`, `discrepancy.service` | `test_dr_models::test_report_from_dict_missing_mandatory_raises` (7 parametrised), `test_dr_service::test_receive_report_missing_mandatory_returns_454` |
| reportType is an enumeration — exactly the 19 DR types defined in §3.7.4–§3.7.22 | §3.7.1 | `discrepancy.models` | `test_dr_models::test_report_types_cover_all_standard_subsections`, `test_report_unknown_report_type_rejected` |
| problemSeverity tokens: Minor/Moderate/Degraded/Impaired/Severe/Critical (exactly 6) | §3.7.1 | `discrepancy.models` | `test_dr_models::test_problem_severity_registry_exact`, `test_report_unknown_severity_rejected` |
| OPTIONAL/CONDITIONAL DR fields absent (not null) when unset | §3.7.1 | `discrepancy.models` | `test_dr_models::test_report_optional_fields_absent_not_null`, `test_response_mandatory_fields_and_optional_absent` |
| reportType-dependent parameters carried as additional top-level members | §3.7.1 | `discrepancy.models` | `test_dr_models::test_report_specific_block_merged_top_level`, `test_report_from_dict_unknown_keys_become_report_specific` |
| resolutionUri JSON key spelled per §3.7.1 (i3 LogEvent URI-uppercasing rule does not apply) | §3.7.1 | `discrepancy.models` | `test_dr_models::test_report_resolution_uri_key_is_not_uppercased` |
| 201 DiscrepancyReportResponse carries MANDATORY respondingAgencyName + respondingContactJcard | §3.7.1 | `discrepancy.service` | `test_dr_service::test_receive_valid_report_returns_201_with_mandatory_response_fields` |
| POST /Reports: 470 Unknown Service/Database when problemService is not ours; 471 Unauthorized Reporter via hook | §3.7.1 | `discrepancy.service` | `test_dr_service::test_problem_service_not_ours_returns_470`, `test_unauthorized_reporter_returns_471_and_nothing_stored` |
| Resolution POSTed to the reporter's resolutionUri call-back ({resolutionUri}/Resolutions); recorded even if call-back fails | §3.7.2 | `discrepancy.service` | `test_dr_service::test_resolve_posts_callback_to_resolution_uri`, `test_resolve_callback_failure_still_records_resolution` |
| GET /Resolutions: 200 with DiscrepancyResolution; 473 Unknown ReportId; 475 Response Not Available Yet | §3.7.2 | `discrepancy.service`, `discrepancy.routes` | `test_dr_service::test_resolve_records_and_serves_resolution`, `test_get_resolution_pending_returns_475`, `test_get_resolution_unknown_report_returns_473` |
| POST /Resolutions receiver: 201 on match; 454 malformed; 472 Unauthorized Responder; 473 unknown/foreign reportId | §3.7.2 | `discrepancy.service` | `test_dr_service::test_receive_resolution_matches_submitted_report`, `test_receive_resolution_unknown_report_returns_473`, `test_receive_resolution_wrong_reporting_agency_returns_473`, `test_receive_resolution_unauthorized_responder_returns_472` |
| GET /StatusUpdates: 200 with MANDATORY responseEstimatedReturnTime; 473 unknown; 474 Resolution Already Provided | §3.7.3 | `discrepancy.service` | `test_dr_service::test_status_update_pending_returns_200_with_estimated_return_time`, `test_status_update_unknown_report_returns_473`, `test_status_update_after_resolution_returns_474` |
| FEs SHOULD rate-limit similar DRs (DoS guard); similarity = reportType + problemService + problem token | §3.7 | `discrepancy.service` | `test_dr_service::test_submit_rate_limits_similar_reports`, `test_submit_dissimilar_reports_not_rate_limited`, `test_submit_force_bypasses_rate_limit` |
| DR timestamps are i3 Timestamps with explicit offset (bare Z rejected); submittal stamp applied at send time | §3.7.1, §2.3 | `discrepancy.models`, `discrepancy.service` | `test_dr_models::test_report_bare_z_timestamp_rejected`, `test_dr_service::test_submit_posts_to_reports_resource_and_stamps_timestamp` |
| Conformance helper `assert_discrepancy_reporting()` exercises all four DR resources; wired into `assert_core_conformance` | §3.7 | `conformance.checks` | `test_dr_routes::test_conformance_helper_passes_for_default_app`, `test_conformance_suite::test_assert_core_conformance_passes_for_minimal_fe` |

---

## NG-SEC coverage — NENA-STA-040.2-2024 (Security for Next Generation 9-1-1)

A separate standard from STA-010.3f-2021; cited here with its own section
numbers (§6.x, §5.6.x) so as not to conflate the two documents. Most of
NG-SEC is organizational/physical (policy, training, facilities) and is out
of scope for a library — the rows below are the parts that bear directly on
code in this package.

| Requirement | NG-SEC section | Module | How verified |
|---|---|---|---|
| Self-signed test-credential generator kept out of the production (`logging`/`security`) import surface | §6.23.8 (self-signed certs MUST NOT be used for ESInet comms), §6.9 (production SHALL NOT contain dev tools) | `testing` | `test_peer_auth::test_make_test_credential_not_importable_from_jws_signer`, `test_make_test_credential_importable_from_testing_module` |
| Verified peer identity exposes Agent identity (rfc822Name SAN, per i3 §5.1 `agentid@agencyid`) and raw otherName SAN entries, not just DNSName/URI | §6.23.1, §6.23.3 (Identifier/Role/Agency-Affiliation carried in the certificate) | `security.peer_auth` | `test_peer_auth::test_verifier_extracts_agent_rfc822_name`, `test_verifier_extracts_other_name_san`, `test_verifier_dns_only_leaf_has_empty_agent_fields` |
| Failed client-certificate authentication returns one generic denial body regardless of cause (missing header / untrusted source / expired / untraceable / malformed) | §6.2.3 (failed authentications SHALL NOT identify the reason for the failure) | `security.peer_auth` | `test_peer_auth::test_missing_and_invalid_cert_return_identical_denial_body`, `test_untrusted_source_returns_same_denial_body_as_missing_cert` |
| Private key field excluded from dataclass repr() | §6.23.7 (private keys SHALL be protected from unauthorized disclosure) | `logging.jws_signer` | `test_jws_signer::test_signer_repr_excludes_private_key` |
