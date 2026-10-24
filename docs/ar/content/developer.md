# دليل المطوّر

للمطوّرين الذين يستدعون واجهة Attome البرمجية من نظام آخر أو يبنون على شيفرته المصدرية.

## الواجهة البرمجية

كل ما يفعله تطبيق الويب يمر عبر الواجهة البرمجية HTTP تحت `/api/v1`. وثيقة OpenAPI متاحة على
`/api/v1/openapi.json` (وفي المستودع باسم `openapi.json`)، ومرجع الواجهة في موقع الوثائق مولَّد منها. أما
`/api/v1/openapi/deployment.json` فيصف كيانات هذا النشر وحقوله.

- **المصادقة**: مفتاح API (`Authorization: Bearer <key>`)، أو جلسة متصفح، أو الدخول عبر OIDC، أو استدعاءات
  خادم لخادم موقّعة بـHMAC للتكاملات.
- **السجلات**: `GET/POST /api/v1/{entity}` و`GET/PATCH/DELETE /api/v1/{entity}/{id}`. يحتاج التعديل إلى
  `If-Match: "<row_version>"` من السجل الذي قرأته، والإصدار القديم يُرد عليه بـ409.
- **الاستعلامات**: `POST /api/v1/query/execute` يشغّل استعلامًا مخزنًا أو عرضًا مع مرشحات وتصفّح بالمؤشر
  (`after_id`) وعدد إجمالي دقيق اختياري.
- **الاستعلامات المنظّمة**: `POST /api/v1/query/run` مع `{spec}` (‏QuerySpec: ‏`entity` و`select` وشجرة `where`
  و`sort` و`page_size` و`cursor`، أو `group_by` و`aggregates` مع `having`) أو `{q}`
  (`SELECT name FROM account WHERE EXISTS(incident.customer WHERE statecode = 0)`)، ومع `params` لقيم `:name`.
  يُسمّى الحقل المرتبط بمساره (`primary_contact.name`). تُستبعد السجلات والحقول التي لا يحق لك قراءتها، و`explain: true`
  يعيد خطة التنفيذ بدل النتائج.
- **القوائم** تجيب بـ`{items, total, page, page_size}` (تبدأ الصفحات من 1)، والقوائم غير المحدودة تستخدم مؤشرًا
  (`next_cursor`).
- **إعادة المحاولة**: أرسل `Idempotency-Key` مع الإنشاء أو الإجراء، فتحصل إعادة المحاولة بالمفتاح نفسه على
  الإجابة الأولى.
- **الأخطاء** بصيغة `application/problem+json` مع رمز `error` ثابت، و422 يسمّي الحقل.
- **الإصدارات**: تشرح [إصدارات الواجهة البرمجية](../api-versions.md) ترويسة `Attome-Version` وكيف يُعلن
  عن التغييرات الكاسرة.
- **التغييرات**: اشتراكات الأحداث (webhooks عبر `/api/v1/admin/events`) تسلّم تغيّرات السجلات إلى نظام آخر،
  مع إعادة المحاولة وقائمة للفاشل، و`GET /api/v1/live` يبثّها لعميل مسجّل الدخول.

يكتب `attome sdk generate <deployment.json>` أنواع Rust وواجهات TypeScript لكيانات النشر.

### التعديلات المتزامنة

لكل سجل قيمة `row_version`. أعِدها في ترويسة `If-Match` مع طلب `PATCH`، فإن كان غيرك قد حفظ السجل بعد
قراءتك له رُفض التعديل بـ`409 version_conflict`، ويذكر جسم الرد ما تغيّر، فتعرض الفروق بدل إعادة التحميل
دون علم:

```http
PATCH /api/v1/deal/0192f0c4-7d1e-7c3a-9b1e-5d6f8a9b0c1d
If-Match: "4"
Content-Type: application/json

{"amount": 125000}
```

```json
{
  "error": "version_conflict",
  "message": "version conflict",
  "current_version": 6,
  "current_state": {
    "last_changed_by": "Sara Ahmed",
    "last_changed_at": "2026-10-19T09:12:44Z",
    "changed_attributes": [
      {"name": "amount", "their_value": 120000,
       "changed_by": "Sara Ahmed", "changed_at": "2026-10-19T09:12:44Z"},
      {"name": "stage", "their_value": "Negotiation",
       "changed_by": "Omar Ali", "changed_at": "2026-10-19T08:55:02Z"}
    ],
    "hidden_changes": 1
  }
}
```

تسرد `changed_attributes` كل خاصية تغيّرت منذ `If-Match` الذي أرسلته، الأحدث أولًا، مع قيمة الكاتب الآخر، وتعدّ
`hidden_changes` التغييرات على حقول لا يحق لك قراءتها، ولا تُعرض قيمها أبدًا. أعد المحاولة بـ`If-Match: "6"`
والقيم التي قررت إبقاءها.

ليدمج الخادم عنك، أضف `If-Match-Merge: attributes`. عندها يُطبَّق التعديل القديم على الإصدار الحالي إن لم
تتغير أي خاصية ترسلها منذ إصدارك، ويسرد رد 200 في `merged_over` الخصائص التي غيّرها غيرك (وتعدّ
`merged_hidden` ما لا يحق لك قراءته منها). ومع `Prefer: return=minimal` يكون الرد:

```json
{"id": "0192f0c4-7d1e-7c3a-9b1e-5d6f8a9b0c1d", "row_version": 7, "merged_over": ["stage"]}
```

وإن غيّر كاتب آخر خاصية ترسلها، أو لم يستطع سجل التغييرات تفسير الإصدارات بين الاثنين، فالرد هو 409 نفسه
أعلاه.

وللمسارات الآلية والوكلاء قاعدة أيضًا. إعداد `on_conflict` في عقدة تحديث السجل هو `retry_fresh` (الافتراضي: يقرأ
السجل من جديد ويطبّق تغييرات العقدة، حتى ثلاث محاولات)، أو `merge` (يكتب فوق الإصدار الذي رآه التشغيل ويدمج كما
يفعل `If-Match-Merge`، وإلا يتوقف)، أو `stop` (تفشل العقدة مع جسم الرد 409)، أو `ask_person` (يفتح طلب موافقة
فيه التعارض؛ عند الموافقة تطبّق العقدة تغييراتها على السجل كما هو حينها، وعند الرفض تفشل). وتحديث الوكيل للسجل
يدمج بالطريقة نفسها، وإن تعذّر الدمج يعود إليه جسم الرد 409 ليقرأ السجل من جديد.

## البناء من المصدر

Rust 1.97 (مثبّت في `rust-toolchain.toml`) على ويندوز أو لينكس، وPostgreSQL 18 مع pgvector لاختبارات
قاعدة البيانات، وNode 22 لتطبيق الويب:

```sh
cargo build -p attome
cd web && npm ci && npm run build:all
attome test --changed
cargo run -p attome-release --target-dir target/gate -- --check
```
