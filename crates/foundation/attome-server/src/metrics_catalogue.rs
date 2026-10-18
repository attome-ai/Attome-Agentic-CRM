//! The metric catalogue (roadmap U4-T2): every metric this server emits,
//! declared once with its kind, unit and meaning in English and Arabic. The
//! admin console reads it (`GET /api/v1/admin/ops/metrics/catalogue`), and a
//! test fails when the code emits a metric the catalogue lacks.

/// One metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct MetricInfo {
    pub name: &'static str,
    /// `counter`, `gauge` or `histogram`.
    pub kind: &'static str,
    pub unit: &'static str,
    pub en: &'static str,
    pub ar: &'static str,
}

/// Every metric, sorted by name.
pub const CATALOGUE: &[MetricInfo] = &[
    MetricInfo {
        name: "ai_delta_publish_failures_total",
        kind: "counter",
        unit: "failures",
        en: "Streamed answer pieces that could not be sent to the browser.",
        ar: "أجزاء إجابة متدفقة تعذّر إرسالها للمتصفح.",
    },
    MetricInfo {
        name: "ai_gate_refusals_total",
        kind: "counter",
        unit: "calls",
        en: "Agent tool calls the gate refused, by reason.",
        ar: "استدعاءات أدوات رفضتها البوابة حسب السبب.",
    },
    MetricInfo {
        name: "ai_model_step_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Time of one model call in an agent turn.",
        ar: "زمن استدعاء نموذج واحد في دور الوكيل.",
    },
    MetricInfo {
        name: "ai_runtime_switch_read_failures_total",
        kind: "counter",
        unit: "reads",
        en: "Failures reading the AI on/off switches.",
        ar: "مرات فشل قراءة مفاتيح تشغيل الذكاء الاصطناعي.",
    },
    MetricInfo {
        name: "ai_tool_call_sweep_total",
        kind: "counter",
        unit: "calls",
        en: "Tool calls reclaimed or expired by the sweep.",
        ar: "استدعاءات أدوات استُعيدت أو انتهت بالمسح.",
    },
    MetricInfo {
        name: "ai_tool_calls_total",
        kind: "counter",
        unit: "calls",
        en: "Tool calls an agent made, by action and outcome.",
        ar: "استدعاءات الأدوات من الوكيل حسب الإجراء والنتيجة.",
    },
    MetricInfo {
        name: "ai_turn_steps",
        kind: "histogram",
        unit: "steps",
        en: "Model steps in one agent turn.",
        ar: "خطوات النموذج في دور وكيل واحد.",
    },
    MetricInfo {
        name: "ai_turns_total",
        kind: "counter",
        unit: "turns",
        en: "Agent turns, by outcome.",
        ar: "أدوار الوكيل حسب النتيجة.",
    },
    MetricInfo {
        name: "apalis_dead_letter_jobs",
        kind: "gauge",
        unit: "jobs",
        en: "Jobs that failed every attempt and wait in the dead-letter list.",
        ar: "المهام التي فشلت كل محاولاتها وتنتظر في قائمة المهام الفاشلة.",
    },
    MetricInfo {
        name: "apalis_listen_reconnects_total",
        kind: "counter",
        unit: "reconnects",
        en: "Times the job queue listener reconnected to the database.",
        ar: "عدد مرات إعادة اتصال مستمع طابور المهام بقاعدة البيانات.",
    },
    MetricInfo {
        name: "apalis_oldest_pending_age_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Age of the oldest job waiting to run.",
        ar: "عمر أقدم مهمة تنتظر التنفيذ.",
    },
    MetricInfo {
        name: "apalis_pending_jobs",
        kind: "gauge",
        unit: "jobs",
        en: "Jobs waiting to run.",
        ar: "المهام التي تنتظر التنفيذ.",
    },
    MetricInfo {
        name: "apalis_pending_jobs_by_priority",
        kind: "gauge",
        unit: "jobs",
        en: "Jobs waiting to run, by priority.",
        ar: "المهام التي تنتظر التنفيذ حسب الأولوية.",
    },
    MetricInfo {
        name: "apalis_retrying_jobs",
        kind: "gauge",
        unit: "jobs",
        en: "Jobs waiting for another attempt after a failure.",
        ar: "المهام التي تنتظر محاولة أخرى بعد فشل.",
    },
    MetricInfo {
        name: "apalis_worker_last_seen_age_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Time since a job worker last reported in.",
        ar: "الوقت منذ آخر ظهور لعامل المهام.",
    },
    MetricInfo {
        name: "approval_auto_decisions_total",
        kind: "counter",
        unit: "decisions",
        en: "Approval requests decided automatically by policy.",
        ar: "طلبات الموافقة التي حسمتها السياسة تلقائيًا.",
    },
    MetricInfo {
        name: "approval_executing_stale",
        kind: "gauge",
        unit: "requests",
        en: "Approved requests stuck while executing.",
        ar: "طلبات موافق عليها عالقة أثناء التنفيذ.",
    },
    MetricInfo {
        name: "approval_expiry_sweep_failed_total",
        kind: "counter",
        unit: "sweeps",
        en: "Failed runs of the approval expiry sweep.",
        ar: "مرات فشل مسح انتهاء صلاحية الموافقات.",
    },
    MetricInfo {
        name: "approval_oldest_pending_age_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Age of the oldest approval request still pending.",
        ar: "عمر أقدم طلب موافقة ما زال معلقًا.",
    },
    MetricInfo {
        name: "approval_requests",
        kind: "gauge",
        unit: "requests",
        en: "Approval requests, by status.",
        ar: "طلبات الموافقة حسب الحالة.",
    },
    MetricInfo {
        name: "approval_requests_expired_total",
        kind: "counter",
        unit: "requests",
        en: "Approval requests that expired undecided.",
        ar: "طلبات الموافقة التي انتهت صلاحيتها دون قرار.",
    },
    MetricInfo {
        name: "attome_ai_injection_flagged_total",
        kind: "counter",
        unit: "items",
        en: "Retrieved content flagged as a possible prompt injection.",
        ar: "محتوى مسترجع مُعلَّم كحقن محتمل للتعليمات.",
    },
    MetricInfo {
        name: "attome_ai_injection_withheld_total",
        kind: "counter",
        unit: "items",
        en: "Retrieved content withheld from the model as a likely prompt injection.",
        ar: "محتوى مسترجع حُجب عن النموذج كحقن محتمل للتعليمات.",
    },
    MetricInfo {
        name: "attome_ai_spend_degraded_total",
        kind: "counter",
        unit: "requests",
        en: "AI requests served by a cheaper model because the budget ran low.",
        ar: "طلبات ذكاء اصطناعي خُدمت بنموذج أرخص لاقتراب نفاد الميزانية.",
    },
    MetricInfo {
        name: "attome_inference_budget_rejected_total",
        kind: "counter",
        unit: "requests",
        en: "Model requests refused because the token budget was spent.",
        ar: "طلبات نموذج رُفضت لنفاد ميزانية الرموز.",
    },
    MetricInfo {
        name: "attome_inference_request_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Time of one model request.",
        ar: "زمن طلب نموذج واحد.",
    },
    MetricInfo {
        name: "attome_inference_requests_total",
        kind: "counter",
        unit: "requests",
        en: "Model requests, by outcome.",
        ar: "طلبات النموذج حسب النتيجة.",
    },
    MetricInfo {
        name: "attome_inference_tokens_total",
        kind: "counter",
        unit: "tokens",
        en: "Model tokens used, by direction.",
        ar: "الرموز المستخدمة في النموذج حسب الاتجاه.",
    },
    MetricInfo {
        name: "attome_model_lookup_miss_total",
        kind: "counter",
        unit: "lookups",
        en: "Lookups of a model object that found nothing.",
        ar: "عمليات البحث عن كائن نموذج لم تجد شيئًا.",
    },
    MetricInfo {
        name: "attome_node_up",
        kind: "gauge",
        unit: "nodes",
        en: "1 for each node that stored its metrics this minute, by node and version.",
        ar: "1 لكل عقدة خزّنت مقاييسها في هذه الدقيقة، حسب العقدة والإصدار.",
    },
    MetricInfo {
        name: "attome_read_only",
        kind: "gauge",
        unit: "flag",
        en: "1 while the deployment is read-only (an operator switch or the database size ceiling).",
        ar: "قيمة 1 ما دام النشر للقراءة فقط (بمفتاح المشغّل أو بلوغ حد حجم قاعدة البيانات).",
    },
    MetricInfo {
        name: "attome_readiness_check",
        kind: "gauge",
        unit: "flag",
        en: "Each readiness check: 1 passing, 0 failing.",
        ar: "كل فحص جاهزية: 1 ناجح و0 فاشل.",
    },
    MetricInfo {
        name: "attome_readiness_probe_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Time of one readiness check.",
        ar: "زمن فحص جاهزية واحد.",
    },
    MetricInfo {
        name: "attome_web_vital_ms",
        kind: "histogram",
        unit: "milliseconds",
        en: "Page speed measured in browsers: largest contentful paint and interaction to next paint, by screen area.",
        ar: "سرعة الصفحات كما تقيسها المتصفحات: أكبر عرض للمحتوى وزمن الاستجابة للتفاعل، حسب منطقة الشاشة.",
    },
    MetricInfo {
        name: "audit_chain_anchor_failures_total",
        kind: "counter",
        unit: "failures",
        en: "Audit chain batches that could not be anchored outside the database.",
        ar: "دفعات سلسلة التدقيق التي تعذّر تثبيتها خارج قاعدة البيانات.",
    },
    MetricInfo {
        name: "audit_chain_batch_events_total",
        kind: "counter",
        unit: "events",
        en: "Audit events sealed into the hash chain.",
        ar: "أحداث التدقيق المختومة في سلسلة التجزئة.",
    },
    MetricInfo {
        name: "audit_chain_epoch_seal_anchor_failures_total",
        kind: "counter",
        unit: "failures",
        en: "Epoch seals of the audit chain that could not be anchored.",
        ar: "أختام الحقب في سلسلة التدقيق التي تعذّر تثبيتها.",
    },
    MetricInfo {
        name: "audit_chainer_lag_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "How far the audit chainer is behind the newest event.",
        ar: "مقدار تأخر مُسلسل التدقيق عن أحدث حدث.",
    },
    MetricInfo {
        name: "audit_chainer_pending_ingest",
        kind: "gauge",
        unit: "events",
        en: "Audit events waiting to be chained.",
        ar: "أحداث التدقيق التي تنتظر السلسلة.",
    },
    MetricInfo {
        name: "audit_ingest_backlog_breaker_tripped",
        kind: "gauge",
        unit: "flag",
        en: "1 when the audit backlog breaker is open and writes are refused.",
        ar: "قيمة 1 عند فتح قاطع تراكم التدقيق ورفض الكتابة.",
    },
    MetricInfo {
        name: "auth_kdf_inflight",
        kind: "gauge",
        unit: "hashes",
        en: "Password hashes being computed now.",
        ar: "عمليات تجزئة كلمات المرور الجارية الآن.",
    },
    MetricInfo {
        name: "auth_kdf_rejected_total",
        kind: "counter",
        unit: "requests",
        en: "Sign-ins refused because password hashing was saturated.",
        ar: "تسجيلات دخول رُفضت لتشبع تجزئة كلمات المرور.",
    },
    MetricInfo {
        name: "auth_kdf_wait_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Wait for a password hashing slot.",
        ar: "زمن انتظار دور في تجزئة كلمات المرور.",
    },
    MetricInfo {
        name: "auth_password_rehash_total",
        kind: "counter",
        unit: "passwords",
        en: "Passwords rehashed to current settings at sign-in.",
        ar: "كلمات مرور أعيدت تجزئتها بالإعدادات الحالية عند الدخول.",
    },
    MetricInfo {
        name: "axum_http_requests_duration_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "HTTP request time, by method, route and status.",
        ar: "زمن طلبات HTTP حسب الطريقة والمسار والحالة.",
    },
    MetricInfo {
        name: "axum_http_requests_pending",
        kind: "gauge",
        unit: "requests",
        en: "HTTP requests in progress.",
        ar: "طلبات HTTP قيد التنفيذ.",
    },
    MetricInfo {
        name: "axum_http_requests_total",
        kind: "counter",
        unit: "requests",
        en: "HTTP requests, by method, route and status.",
        ar: "طلبات HTTP حسب الطريقة والمسار والحالة.",
    },
    MetricInfo {
        name: "base_cache_redis_ops_total",
        kind: "counter",
        unit: "operations",
        en: "Cache operations against Redis, by outcome.",
        ar: "عمليات التخزين المؤقت على Redis حسب النتيجة.",
    },
    MetricInfo {
        name: "capability_rejections_total",
        kind: "counter",
        unit: "requests",
        en: "Requests refused because a dependency they need is down.",
        ar: "طلبات رُفضت لتعطل خدمة تحتاجها.",
    },
    MetricInfo {
        name: "capability_state",
        kind: "gauge",
        unit: "state",
        en: "Each optional dependency's state: 1 up, 0 down.",
        ar: "حالة كل خدمة اختيارية: 1 تعمل و0 متوقفة.",
    },
    MetricInfo {
        name: "change_feed_consumer_expired_total",
        kind: "counter",
        unit: "consumers",
        en: "Change-feed consumers expired for falling too far behind.",
        ar: "مستهلكو موجز التغييرات الذين انتهت صلاحيتهم لتأخرهم كثيرًا.",
    },
    MetricInfo {
        name: "change_feed_consumer_lag_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Age of each change-feed consumer's oldest unread event.",
        ar: "عمر أقدم حدث لم يقرأه كل مستهلك لموجز التغييرات.",
    },
    MetricInfo {
        name: "db_bloat_dead_tuples",
        kind: "gauge",
        unit: "rows",
        en: "Dead rows waiting for vacuum, by table.",
        ar: "الصفوف الميتة التي تنتظر التنظيف حسب الجدول.",
    },
    MetricInfo {
        name: "db_bloat_live_tuples",
        kind: "gauge",
        unit: "rows",
        en: "Live rows, by table.",
        ar: "الصفوف الحية حسب الجدول.",
    },
    MetricInfo {
        name: "db_bloat_seconds_since_last_autovacuum",
        kind: "gauge",
        unit: "seconds",
        en: "Time since a table was last vacuumed automatically.",
        ar: "الوقت منذ آخر تنظيف تلقائي للجدول.",
    },
    MetricInfo {
        name: "db_bloat_total_bytes",
        kind: "gauge",
        unit: "bytes",
        en: "Table size on disk.",
        ar: "حجم الجدول على القرص.",
    },
    MetricInfo {
        name: "db_migrator_pool_idle",
        kind: "gauge",
        unit: "connections",
        en: "Idle connections in the migrator pool.",
        ar: "الاتصالات الخاملة في مجمع اتصالات الترحيل.",
    },
    MetricInfo {
        name: "db_migrator_pool_size",
        kind: "gauge",
        unit: "connections",
        en: "Connections in the migrator pool.",
        ar: "الاتصالات في مجمع اتصالات الترحيل.",
    },
    MetricInfo {
        name: "db_pool_acquire_timeouts_total",
        kind: "counter",
        unit: "timeouts",
        en: "Waits for a database connection that timed out.",
        ar: "مرات انتهاء مهلة انتظار اتصال بقاعدة البيانات.",
    },
    MetricInfo {
        name: "db_pool_acquire_wait_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Wait for a database connection, by pool.",
        ar: "زمن انتظار اتصال بقاعدة البيانات حسب المجمع.",
    },
    MetricInfo {
        name: "db_pool_idle",
        kind: "gauge",
        unit: "connections",
        en: "Idle connections in the main pool.",
        ar: "الاتصالات الخاملة في المجمع الرئيسي.",
    },
    MetricInfo {
        name: "db_pool_role_acquire_timeouts_total",
        kind: "counter",
        unit: "timeouts",
        en: "Connection waits that timed out, by pool role.",
        ar: "مرات انتهاء مهلة انتظار اتصال حسب دور المجمع.",
    },
    MetricInfo {
        name: "db_pool_size",
        kind: "gauge",
        unit: "connections",
        en: "Connections in the main pool.",
        ar: "الاتصالات في المجمع الرئيسي.",
    },
    MetricInfo {
        name: "db_readonly_pool_idle",
        kind: "gauge",
        unit: "connections",
        en: "Idle connections to the read replica.",
        ar: "الاتصالات الخاملة بنسخة القراءة.",
    },
    MetricInfo {
        name: "db_readonly_pool_size",
        kind: "gauge",
        unit: "connections",
        en: "Connections to the read replica.",
        ar: "الاتصالات بنسخة القراءة.",
    },
    MetricInfo {
        name: "db_readonly_primary_pool_idle",
        kind: "gauge",
        unit: "connections",
        en: "Idle read-only connections to the primary.",
        ar: "اتصالات القراءة الخاملة بالخادم الرئيسي.",
    },
    MetricInfo {
        name: "db_readonly_primary_pool_size",
        kind: "gauge",
        unit: "connections",
        en: "Read-only connections to the primary.",
        ar: "اتصالات القراءة بالخادم الرئيسي.",
    },
    MetricInfo {
        name: "db_replica_lag_bytes",
        kind: "gauge",
        unit: "bytes",
        en: "How far the read replica is behind, in WAL bytes.",
        ar: "مقدار تأخر نسخة القراءة بوحدات سجل WAL.",
    },
    MetricInfo {
        name: "db_replica_lag_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "How far the read replica is behind, in time.",
        ar: "مقدار تأخر نسخة القراءة زمنيًا.",
    },
    MetricInfo {
        name: "db_statement_timeouts_total",
        kind: "counter",
        unit: "statements",
        en: "Database statements cancelled by their time limit.",
        ar: "استعلامات أُلغيت لتجاوز حدها الزمني.",
    },
    MetricInfo {
        name: "db_tx_retries_total",
        kind: "counter",
        unit: "retries",
        en: "Transactions run again after a serialization failure or deadlock, by class.",
        ar: "معاملات أُعيد تشغيلها بعد تعارض تسلسلي أو جمود، حسب الفئة.",
    },
    MetricInfo {
        name: "db_tx_retry_exhausted_total",
        kind: "counter",
        unit: "transactions",
        en: "Transactions that still conflicted after every retry, by class.",
        ar: "معاملات بقي فيها التعارض بعد كل المحاولات، حسب الفئة.",
    },
    MetricInfo {
        name: "db_unpooled_sessions_open",
        kind: "gauge",
        unit: "sessions",
        en: "Database sessions open outside the pools.",
        ar: "جلسات قاعدة البيانات المفتوحة خارج المجمعات.",
    },
    MetricInfo {
        name: "email_send_duration_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Time to hand an email to the mail server.",
        ar: "زمن تسليم بريد إلى خادم البريد.",
    },
    MetricInfo {
        name: "email_send_total",
        kind: "counter",
        unit: "emails",
        en: "Emails sent, by outcome.",
        ar: "رسائل البريد المرسلة حسب النتيجة.",
    },
    MetricInfo {
        name: "email_suppression_added_total",
        kind: "counter",
        unit: "addresses",
        en: "Addresses added to the do-not-send list after a bounce or complaint.",
        ar: "عناوين أضيفت إلى قائمة عدم الإرسال بعد ارتداد أو شكوى.",
    },
    MetricInfo {
        name: "events_dead_lettered_total",
        kind: "counter",
        unit: "deliveries",
        en: "Event deliveries given up after every retry.",
        ar: "تسليمات أحداث أُلغيت بعد استنفاد المحاولات.",
    },
    MetricInfo {
        name: "events_dead_letters",
        kind: "gauge",
        unit: "deliveries",
        en: "Event deliveries that failed for good.",
        ar: "تسليمات الأحداث الفاشلة نهائيًا.",
    },
    MetricInfo {
        name: "events_deliveries_retrying",
        kind: "gauge",
        unit: "deliveries",
        en: "Event deliveries waiting to retry.",
        ar: "تسليمات الأحداث التي تنتظر إعادة المحاولة.",
    },
    MetricInfo {
        name: "events_deliveries_total",
        kind: "counter",
        unit: "deliveries",
        en: "Event deliveries attempted, by outcome.",
        ar: "محاولات تسليم الأحداث حسب النتيجة.",
    },
    MetricInfo {
        name: "events_delivery_attempt_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Time of one event delivery attempt.",
        ar: "زمن محاولة تسليم حدث واحدة.",
    },
    MetricInfo {
        name: "events_delivery_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Time from an event to its delivery.",
        ar: "الزمن من وقوع الحدث حتى تسليمه.",
    },
    MetricInfo {
        name: "events_dispatch_failures_total",
        kind: "counter",
        unit: "failures",
        en: "Events that could not be handed to subscribers.",
        ar: "أحداث تعذّر تسليمها للمشتركين.",
    },
    MetricInfo {
        name: "events_dispatched_total",
        kind: "counter",
        unit: "events",
        en: "Events handed to subscribers.",
        ar: "الأحداث المسلَّمة للمشتركين.",
    },
    MetricInfo {
        name: "events_subscription_lag_max",
        kind: "gauge",
        unit: "events",
        en: "The most events any subscription is behind.",
        ar: "أكبر تأخر لأي اشتراك بعدد الأحداث.",
    },
    MetricInfo {
        name: "hot_cache_lookups_total",
        kind: "counter",
        unit: "lookups",
        en: "In-memory cache lookups, by hit or miss.",
        ar: "عمليات البحث في الذاكرة المؤقتة الداخلية حسب الإصابة.",
    },
    MetricInfo {
        name: "idempotency_durable_non_atomic_completion_total",
        kind: "counter",
        unit: "requests",
        en: "Retried requests whose stored outcome could not be written with the change.",
        ar: "طلبات مكررة تعذّر حفظ نتيجتها مع التغيير نفسه.",
    },
    MetricInfo {
        name: "idempotency_marker_write_failures_total",
        kind: "counter",
        unit: "requests",
        en: "Failures writing the marker that makes a retried request safe.",
        ar: "مرات فشل كتابة علامة أمان الطلب المكرر.",
    },
    MetricInfo {
        name: "idempotency_mismatch_total",
        kind: "counter",
        unit: "requests",
        en: "Retries refused because the key was used for a different request, by operation.",
        ar: "طلبات مكررة رُفضت لأن المفتاح استُخدم لطلب مختلف، حسب العملية.",
    },
    MetricInfo {
        name: "idempotency_pending_stuck",
        kind: "gauge",
        unit: "keys",
        en: "Durable idempotency keys still pending ten minutes after they were taken.",
        ar: "مفاتيح منع التكرار التي ما زالت معلّقة بعد عشر دقائق من أخذها.",
    },
    MetricInfo {
        name: "idempotency_replays_total",
        kind: "counter",
        unit: "requests",
        en: "Retried requests answered with the original response, by operation.",
        ar: "طلبات مكررة أُجيبت بالاستجابة الأصلية، حسب العملية.",
    },
    MetricInfo {
        name: "idempotency_unknown_total",
        kind: "counter",
        unit: "requests",
        en: "Retries answered that the original's outcome is unknown, by operation.",
        ar: "طلبات مكررة أُجيبت بأن نتيجة الطلب الأصلي غير معروفة، حسب العملية.",
    },
    MetricInfo {
        name: "integration_webhook_total",
        kind: "counter",
        unit: "webhooks",
        en: "Incoming integration webhooks, by outcome.",
        ar: "إشعارات التكامل الواردة حسب النتيجة.",
    },
    MetricInfo {
        name: "job_schedule_last_success_age_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Time since each scheduled job last succeeded.",
        ar: "الوقت منذ آخر نجاح لكل مهمة مجدولة.",
    },
    MetricInfo {
        name: "limit_hits_total",
        kind: "counter",
        unit: "hits",
        en: "Requests a limit refused, by limit and kind of caller.",
        ar: "طلبات رفضها حدٌّ ما، حسب الحد ونوع المستدعي.",
    },
    MetricInfo {
        name: "metadata_pin_unavailable_total",
        kind: "counter",
        unit: "requests",
        en: "Requests refused because this node could not catch up to the caller's own metadata write in time.",
        ar: "طلبات رُفضت لأن هذه العقدة لم تلحق في الوقت المناسب بتعديل البيانات الوصفية الذي أجراه المستخدم نفسه.",
    },
    MetricInfo {
        name: "object_storage_probe_latency_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Response time of the file store's health probe.",
        ar: "زمن استجابة فحص سلامة مخزن الملفات.",
    },
    MetricInfo {
        name: "object_storage_up",
        kind: "gauge",
        unit: "flag",
        en: "1 when the file store answers.",
        ar: "قيمة 1 عندما يستجيب مخزن الملفات.",
    },
    MetricInfo {
        name: "platform_job_duration_seconds",
        kind: "histogram",
        unit: "seconds",
        en: "Run time of background jobs, by kind.",
        ar: "زمن تنفيذ المهام الخلفية حسب النوع.",
    },
    MetricInfo {
        name: "platform_jobs_total",
        kind: "counter",
        unit: "jobs",
        en: "Background jobs run, by kind and outcome.",
        ar: "المهام الخلفية المنفذة حسب النوع والنتيجة.",
    },
    MetricInfo {
        name: "portal_auth_total",
        kind: "counter",
        unit: "sign-ins",
        en: "Portal sign-ins, by outcome.",
        ar: "تسجيلات الدخول إلى البوابة حسب النتيجة.",
    },
    MetricInfo {
        name: "portal_cache_bypass_total",
        kind: "counter",
        unit: "requests",
        en: "Portal requests that skipped the cache.",
        ar: "طلبات البوابة التي تجاوزت التخزين المؤقت.",
    },
    MetricInfo {
        name: "portal_cache_invalidation_failed_total",
        kind: "counter",
        unit: "failures",
        en: "Portal cache clears that failed.",
        ar: "مرات فشل مسح ذاكرة البوابة المؤقتة.",
    },
    MetricInfo {
        name: "portal_plan_match_nothing_total",
        kind: "counter",
        unit: "requests",
        en: "Portal reads whose access plan matched no records.",
        ar: "قراءات البوابة التي لم تطابق خطة وصولها أي سجل.",
    },
    MetricInfo {
        name: "profiler_enabled",
        kind: "gauge",
        unit: "flag",
        en: "1 when the request profiler is on.",
        ar: "قيمة 1 عند تشغيل محلل الطلبات.",
    },
    MetricInfo {
        name: "profiler_points_dropped_total",
        kind: "counter",
        unit: "points",
        en: "Profiler samples dropped under load.",
        ar: "عينات المحلل المهملة تحت الضغط.",
    },
    MetricInfo {
        name: "read_routing_decisions_total",
        kind: "counter",
        unit: "reads",
        en: "Reads sent to the replica or the primary, by reason.",
        ar: "القراءات الموجهة إلى النسخة أو الخادم الرئيسي حسب السبب.",
    },
    MetricInfo {
        name: "redis_coordination_maxmemory_bytes",
        kind: "gauge",
        unit: "bytes",
        en: "Memory limit of the coordination Redis.",
        ar: "حد ذاكرة Redis التنسيق.",
    },
    MetricInfo {
        name: "redis_coordination_persistence_changes_since_save",
        kind: "gauge",
        unit: "changes",
        en: "Changes in the coordination Redis since its last save.",
        ar: "التغييرات في Redis التنسيق منذ آخر حفظ.",
    },
    MetricInfo {
        name: "redis_coordination_persistence_last_save_age_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Time since the coordination Redis last saved to disk.",
        ar: "الوقت منذ آخر حفظ لـ Redis التنسيق على القرص.",
    },
    MetricInfo {
        name: "redis_coordination_persistence_policy_configured",
        kind: "gauge",
        unit: "flag",
        en: "1 when the coordination Redis is set to persist.",
        ar: "قيمة 1 عند ضبط Redis التنسيق على الحفظ الدائم.",
    },
    MetricInfo {
        name: "redis_coordination_ping_ms",
        kind: "gauge",
        unit: "milliseconds",
        en: "Round trip to the coordination Redis.",
        ar: "زمن الذهاب والإياب إلى Redis التنسيق.",
    },
    MetricInfo {
        name: "redis_coordination_up",
        kind: "gauge",
        unit: "flag",
        en: "1 when the coordination Redis answers.",
        ar: "قيمة 1 عندما يستجيب Redis التنسيق.",
    },
    MetricInfo {
        name: "redis_coordination_used_memory_bytes",
        kind: "gauge",
        unit: "bytes",
        en: "Memory used by the coordination Redis.",
        ar: "الذاكرة المستخدمة في Redis التنسيق.",
    },
    MetricInfo {
        name: "redis_ping_ms",
        kind: "gauge",
        unit: "milliseconds",
        en: "Round trip to the cache Redis.",
        ar: "زمن الذهاب والإياب إلى Redis التخزين المؤقت.",
    },
    MetricInfo {
        name: "redis_subscriber_clients_created_total",
        kind: "counter",
        unit: "clients",
        en: "Redis subscriber connections opened.",
        ar: "اتصالات اشتراك Redis المفتوحة.",
    },
    MetricInfo {
        name: "redis_up",
        kind: "gauge",
        unit: "flag",
        en: "1 when the cache Redis answers.",
        ar: "قيمة 1 عندما يستجيب Redis التخزين المؤقت.",
    },
    MetricInfo {
        name: "registry_catchup_entities_total",
        kind: "counter",
        unit: "entities",
        en: "Entity definitions reloaded after a metadata change elsewhere.",
        ar: "تعريفات كيانات أعيد تحميلها بعد تغيير في مكان آخر.",
    },
    MetricInfo {
        name: "registry_watermark_lag",
        kind: "gauge",
        unit: "changes",
        en: "Metadata changes this server has not loaded yet.",
        ar: "تغييرات البيانات الوصفية التي لم يحملها هذا الخادم بعد.",
    },
    MetricInfo {
        name: "registry_watermark_poll_forced_catchup_total",
        kind: "counter",
        unit: "polls",
        en: "Metadata polls that had to reload changes.",
        ar: "استطلاعات البيانات الوصفية التي اضطرت لإعادة التحميل.",
    },
    MetricInfo {
        name: "registry_watermark_poll_forced_rebuild_total",
        kind: "counter",
        unit: "polls",
        en: "Metadata polls that rebuilt the whole registry.",
        ar: "استطلاعات البيانات الوصفية التي أعادت بناء السجل كاملًا.",
    },
    MetricInfo {
        name: "s2s_access_log_stream_pending",
        kind: "gauge",
        unit: "entries",
        en: "Server-to-server access log entries waiting to be written.",
        ar: "قيود سجل الوصول بين الخوادم التي تنتظر الكتابة.",
    },
    MetricInfo {
        name: "security_rejection_total",
        kind: "counter",
        unit: "requests",
        en: "Requests refused by a security check, by reason.",
        ar: "طلبات رفضها فحص أمني حسب السبب.",
    },
    MetricInfo {
        name: "storage_presign_failures_total",
        kind: "counter",
        unit: "failures",
        en: "Failures signing a file upload or download link.",
        ar: "مرات فشل توقيع رابط رفع أو تنزيل ملف.",
    },
    MetricInfo {
        name: "stream_buffer_entries_lost_total",
        kind: "counter",
        unit: "entries",
        en: "Buffered stream entries lost before they were written.",
        ar: "قيود التدفق المؤقتة المفقودة قبل كتابتها.",
    },
    MetricInfo {
        name: "upload_scan_backlog_oldest_seconds",
        kind: "gauge",
        unit: "seconds",
        en: "Age of the oldest upload waiting for a virus scan.",
        ar: "عمر أقدم ملف مرفوع ينتظر فحص الفيروسات.",
    },
    MetricInfo {
        name: "upload_scan_backlog_pending",
        kind: "gauge",
        unit: "files",
        en: "Uploads waiting for a virus scan.",
        ar: "الملفات المرفوعة التي تنتظر فحص الفيروسات.",
    },
    MetricInfo {
        name: "workflow_chain_depth_stops_total",
        kind: "counter",
        unit: "runs",
        en: "Workflow runs not started because a chain of workflows reached its depth limit.",
        ar: "تشغيلات سير العمل التي لم تبدأ لأن سلسلة سير العمل بلغت حدها الأقصى من العمق.",
    },
    MetricInfo {
        name: "workflow_trigger_dead_letters_total",
        kind: "counter",
        unit: "triggers",
        en: "Workflow triggers given up after every retry.",
        ar: "مشغلات سير العمل الملغاة بعد استنفاد المحاولات.",
    },
];

/// The catalogue entry for `name`.
pub fn describe(name: &str) -> Option<&'static MetricInfo> {
    CATALOGUE.iter().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The text after `macro!(` up to the first `,` or `)`, trimmed.
    fn first_argument(rest: &str) -> &str {
        let end = rest.find([',', ')']).unwrap_or(rest.len());
        rest[..end].trim()
    }

    /// Every metric name the workspace's code emits: string literals in
    /// `counter!`/`gauge!`/`histogram!`, and constants they name, resolved
    /// through `const NAME: &str = "...";` declarations.
    fn emitted_names() -> BTreeSet<String> {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        rust_files(&crates, &mut files);
        let mut consts: BTreeMap<String, String> = BTreeMap::new();
        let mut literal = BTreeSet::new();
        let mut idents = BTreeSet::new();
        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line
                    .strip_prefix("pub const ")
                    .or_else(|| line.strip_prefix("const "))
                    && let Some((ident, value)) = rest.split_once(": &str = \"")
                    && let Some(value) = value.strip_suffix("\";")
                {
                    consts.insert(ident.trim().to_owned(), value.to_owned());
                }
            }
            for macro_name in ["counter!(", "gauge!(", "histogram!("] {
                let mut rest = text.as_str();
                while let Some(at) = rest.find(macro_name) {
                    rest = &rest[at + macro_name.len()..];
                    let arg = first_argument(rest);
                    if let Some(name) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
                        literal.insert(name.to_owned());
                    } else if !arg.is_empty() {
                        let ident = arg.rsplit("::").next().unwrap_or(arg);
                        if ident
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                        {
                            idents.insert(ident.to_owned());
                        }
                    }
                }
            }
        }
        for ident in idents {
            if let Some(value) = consts.get(&ident) {
                literal.insert(value.clone());
            }
        }
        literal
    }

    #[test]
    fn every_emitted_metric_is_in_the_catalogue() {
        let emitted = emitted_names();
        assert!(
            emitted.len() > 50,
            "the scan found the workspace: {}",
            emitted.len()
        );
        let missing: Vec<&String> = emitted.iter().filter(|n| describe(n).is_none()).collect();
        assert!(
            missing.is_empty(),
            "metrics missing from the catalogue: {missing:?}"
        );
    }

    #[test]
    fn catalogue_entries_are_complete_and_sorted() {
        let mut previous = "";
        for m in CATALOGUE {
            assert!(m.name > previous, "{} is out of order or repeated", m.name);
            previous = m.name;
            assert!(
                ["counter", "gauge", "histogram"].contains(&m.kind),
                "{}",
                m.name
            );
            assert!(
                !m.unit.is_empty() && !m.en.is_empty() && !m.ar.is_empty(),
                "{}",
                m.name
            );
        }
    }
}
