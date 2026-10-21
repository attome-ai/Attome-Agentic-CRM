//! Z14-T3: every error code's message in English and Arabic, for an error
//! response's `title`. The request-id body layer (`attome-server`) picks the
//! language from `Accept-Language` ([`from_accept_language`]); English is
//! the default. `detail` stays the server's own text (it can name a field
//! or a value), so a client shows `title` to people and logs `detail`.

/// A language an error title is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ar,
}

impl Lang {
    /// The `Content-Language` tag.
    pub fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ar => "ar",
        }
    }
}

/// `(code, English, Arabic)` for every code in [`crate::error_codes::ERROR_CODES`].
const MESSAGES: &[(&str, &str, &str)] = &[
    (
        "not_found",
        "The resource was not found.",
        "لم يُعثر على المورد.",
    ),
    (
        "unauthorized",
        "Sign in to continue.",
        "سجّل الدخول للمتابعة.",
    ),
    (
        "forbidden",
        "You do not have permission to do this.",
        "ليست لديك صلاحية للقيام بهذا.",
    ),
    (
        "attribute_not_writable",
        "You may not change this field.",
        "لا يمكنك تغيير هذا الحقل.",
    ),
    (
        "limit_exceeded",
        "The request is over a limit.",
        "الطلب يتجاوز حدًّا مسموحًا.",
    ),
    (
        "conflict",
        "The request conflicts with the current state.",
        "يتعارض الطلب مع الحالة الحالية.",
    ),
    (
        "version_conflict",
        "The record was changed by someone else. Reload it and try again.",
        "غيّر شخص آخر هذا السجل. أعد تحميله وحاول مرة أخرى.",
    ),
    (
        "duplicate_detected",
        "This looks like a duplicate of an existing record.",
        "يبدو هذا تكرارًا لسجل موجود.",
    ),
    (
        "idempotency_conflict",
        "This request key was already used for a different request.",
        "استُخدم مفتاح هذا الطلب من قبل لطلب مختلف.",
    ),
    (
        "validation_error",
        "Some values are not valid.",
        "بعض القيم غير صالحة.",
    ),
    (
        "customer_tests_failed",
        "Your tests for this change failed.",
        "فشلت اختباراتك لهذا التغيير.",
    ),
    (
        "rule_violation",
        "A business rule refused this change.",
        "رفضت قاعدة عمل هذا التغيير.",
    ),
    ("field_locked", "This field is locked.", "هذا الحقل مقفل."),
    (
        "field_locked_required",
        "A required field is locked.",
        "حقل مطلوب مقفل.",
    ),
    (
        "feature_unavailable",
        "This feature is not available.",
        "هذه الميزة غير متاحة.",
    ),
    (
        "feature_hidden",
        "This feature is not enabled for this deployment.",
        "هذه الميزة غير مفعّلة في هذا النشر.",
    ),
    (
        "rate_limit_exceeded",
        "Too many requests. Wait a moment and try again.",
        "طلبات كثيرة جدًا. انتظر قليلًا وحاول مرة أخرى.",
    ),
    (
        "overloaded",
        "The server is busy. Try again shortly.",
        "الخادم مشغول. حاول مرة أخرى بعد قليل.",
    ),
    (
        "capability_unavailable",
        "A service this needs is unavailable. Try again shortly.",
        "خدمة يحتاجها هذا غير متاحة. حاول مرة أخرى بعد قليل.",
    ),
    (
        "metadata_authoring_locked",
        "Changes to the data model are locked right now.",
        "تعديل نموذج البيانات مقفل حاليًا.",
    ),
    (
        "transition_not_allowed",
        "This status change is not allowed.",
        "تغيير الحالة هذا غير مسموح.",
    ),
    (
        "reauth_required",
        "Confirm your identity to continue.",
        "أكّد هويتك للمتابعة.",
    ),
    (
        "server_timeout",
        "The server took too long to answer.",
        "استغرق الخادم وقتًا طويلًا في الرد.",
    ),
    (
        "query_timeout",
        "The query took too long. Narrow it and try again.",
        "استغرق الاستعلام وقتًا طويلًا. ضيّق نطاقه وحاول مرة أخرى.",
    ),
    (
        "read_only",
        "The system is read-only right now.",
        "النظام في وضع القراءة فقط حاليًا.",
    ),
    (
        "payload_too_large",
        "The request is too large.",
        "الطلب كبير جدًا.",
    ),
    ("request_rejected", "The request was refused.", "رُفض الطلب."),
    (
        "invalid_cursor",
        "This page link is not valid. Start again from the first page.",
        "رابط الصفحة هذا غير صالح. ابدأ من الصفحة الأولى.",
    ),
    (
        "idempotency_outcome_unknown",
        "It is not known whether the earlier request finished. Check before retrying.",
        "لا يُعرف إن كان الطلب السابق قد اكتمل. تحقّق قبل إعادة المحاولة.",
    ),
    (
        "idempotency_replay_unavailable",
        "The earlier answer to this request cannot be replayed.",
        "لا يمكن إعادة الرد السابق على هذا الطلب.",
    ),
    (
        "method_not_allowed",
        "This action is not supported here.",
        "هذا الإجراء غير مدعوم هنا.",
    ),
    (
        "api_version_sunset",
        "This API version is no longer served.",
        "لم يعد إصدار الواجهة البرمجية هذا متاحًا.",
    ),
    (
        "unsupported_api_version",
        "This API version is not supported.",
        "إصدار الواجهة البرمجية هذا غير مدعوم.",
    ),
    (
        "internal_error",
        "Something went wrong on the server.",
        "حدث خطأ في الخادم.",
    ),
];

/// `code`'s message in `lang`, if the code is catalogued.
pub fn title(code: &str, lang: Lang) -> Option<&'static str> {
    MESSAGES
        .iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, en, ar)| match lang {
            Lang::En => *en,
            Lang::Ar => *ar,
        })
}

/// The language `Accept-Language` prefers among the two this catalogue has:
/// the highest-weighted `ar*` or `en*` range, the first on a tie; English
/// when the header is absent or names neither.
pub fn from_accept_language(header: Option<&str>) -> Lang {
    let Some(header) = header else {
        return Lang::En;
    };
    let mut best: Option<(f32, Lang)> = None;
    for part in header.split(',') {
        let mut pieces = part.split(';');
        let range = pieces
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let weight = pieces
            .find_map(|p| p.trim().strip_prefix("q="))
            .and_then(|q| q.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        let lang = match range.split('-').next() {
            Some("ar") => Lang::Ar,
            Some("en") => Lang::En,
            _ => continue,
        };
        if weight > 0.0 && best.is_none_or(|(w, _)| weight > w) {
            best = Some((weight, lang));
        }
    }
    best.map_or(Lang::En, |(_, lang)| lang)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_has_both_messages() {
        for code in crate::error_codes::ERROR_CODES {
            let en = title(code.code, Lang::En);
            let ar = title(code.code, Lang::Ar);
            assert!(
                en.is_some_and(|t| !t.is_empty()),
                "{} has no English message",
                code.code
            );
            assert!(
                ar.is_some_and(|t| !t.is_empty()),
                "{} has no Arabic message",
                code.code
            );
        }
        assert_eq!(
            MESSAGES.len(),
            crate::error_codes::ERROR_CODES.len(),
            "no stray codes"
        );
    }

    #[test]
    fn accept_language_picks_the_preferred_of_the_two() {
        assert_eq!(from_accept_language(None), Lang::En);
        assert_eq!(
            from_accept_language(Some("ar-SA,ar;q=0.9,en;q=0.8")),
            Lang::Ar
        );
        assert_eq!(
            from_accept_language(Some("en-US,en;q=0.9,ar;q=0.8")),
            Lang::En
        );
        assert_eq!(from_accept_language(Some("fr-FR, ar;q=0.5")), Lang::Ar);
        assert_eq!(from_accept_language(Some("fr-FR")), Lang::En);
        assert_eq!(from_accept_language(Some("ar;q=0, en;q=0.1")), Lang::En);
    }
}
