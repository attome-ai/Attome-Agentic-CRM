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

## البناء من المصدر

Rust 1.97 (مثبّت في `rust-toolchain.toml`) على ويندوز أو لينكس، وPostgreSQL 18 مع pgvector لاختبارات
قاعدة البيانات، وNode 22 لتطبيق الويب:

```sh
cargo build -p attome
cd web && npm ci && npm run build:all
attome test --changed
cargo run -p attome-release --target-dir target/gate -- --check
```
