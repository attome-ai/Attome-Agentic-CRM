# دليل التثبيت

يتكوّن Attome من برنامج واحد هو `attome` (و`attome.exe` على ويندوز) وتطبيق الويب الخاص به، إضافة إلى
قاعدة بيانات PostgreSQL 18 مع امتداد `pgvector`. لا يحتاج الخادم الواحد (Solo) إلى شيء آخر: فذاكرته
المؤقتة وحدود الطلبات والتنسيق كلها في ذاكرة البرنامج. أما Redis أو Dragonfly ومخزن الملفات وماسح
الفيروسات فاختيارية، ولا تلزم إلا عند تعدد الخوادم أو رفع الملفات.

الحد الأدنى للخادم الواحد: معالجان، و4 غيغابايت من الذاكرة، و20 غيغابايت من المساحة الحرة. يتحقق
`attome init` من ذلك، ويرفض التثبيت إذا قلّت المساحة الحرة عن 5 غيغابايت.

## لينكس

أمر واحد يثبّت أحدث إصدار كخدمة systemd. وإذا لم تُعطِه `--database-url` فإنه يثبّت أيضًا PostgreSQL 18
مع pgvector من مستودع مشروع PostgreSQL نفسه (Debian وUbuntu وRHEL وRocky وAlma وFedora):

```sh
curl -fsSL https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.sh \
  | sudo sh -s -- --admin you@example.com
```

الخيارات: `--database-url <url>` لاستخدام قاعدة بيانات موجودة، و`--version <tag>` لإصدار غير الأحدث،
و`--port <n>` (الافتراضي 7865)، و`--prefix <dir>` (الافتراضي `/opt/attome`)، و`--packs <a,b>` (الافتراضي
`crm`، والقائمة الفارغة لا تثبّت شيئًا).

يوضع البرنامج في `/opt/attome` وإعداداته في `/var/lib/attome/config.json`.

## ويندوز

من PowerShell بصلاحيات المسؤول، على قاعدة بيانات PostgreSQL 18 موجودة:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.ps1))) `
    -DatabaseUrl 'postgres://attome_owner:secret@127.0.0.1:5432/attome' -Admin you@example.com
```

لا يوفّر pgvector مثبّتًا لويندوز، لذا يجب تجهيز القاعدة أولًا: دور يملك صلاحية `CREATEROLE` يملك القاعدة،
ومستخدم بصلاحيات كاملة نفّذ:

```sql
CREATE EXTENSION vector;
CREATE EXTENSION pg_trgm;
CREATE EXTENSION pgcrypto;
```

يوضع البرنامج في `%ProgramFiles%\Attome` وإعداداته في `%ProgramData%\Attome\config.json`، ويعمل كخدمة
ويندوز. ويختار `-Packs crm,sales` الحزم كما في لينكس.

## تشغيل PostgreSQL داخل Docker

يعمل Attome نفسه مباشرة على النظام، لكن يمكن تشغيل قاعدة بياناته داخل Docker (Docker Desktop على
ويندوز)، وهي أسهل طريقة للحصول على pgvector على ويندوز:

```sh
docker run -d --name attome-db -p 5432:5432 \
  -e POSTGRES_USER=attome_owner -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=attome \
  -v attome-db:/var/lib/postgresql/data pgvector/pgvector:pg18
docker exec attome-db psql -U attome_owner -d attome \
  -c "CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS pgcrypto;"
```

ثم ثبّت مع `--database-url postgres://attome_owner:secret@127.0.0.1:5432/attome`. واحفظ وحدة التخزين
(`attome-db`) على قرص يشمله النسخ الاحتياطي.

## بعد التثبيت

يستجيب الخادم وتطبيق الويب على `http://localhost:7865/`. سجّل الدخول ببريد المسؤول وكلمة المرور المؤقتة
التي طبعها التثبيت، ثم:

1. أعِدّ النشر لبلدك: معالج الإعداد الأول (`/xrm/admin/first-run`) يثبّت إعدادات المنطقة (العملة ونسب
   ضريبة القيمة المضافة وصيغ الهوية وأيام العمل والعطل) ويضبط اللغة والمنطقة الزمنية والتقويم.
2. افحص الخادم: `attome status` يعرض إصدار كل خادم وجاهزيته، و`attome doctor` يفحص الإعدادات والاعتماديات
   ويقول ما يجب فعله لكل خلل.
3. خطّط للنسخ الاحتياطي: `attome backup now` يكتب نسخة، و`attome backup drill` يثبت أنها تُستعاد.
4. اقرأ [دليل المسؤول](admin.md).

## يدويًا

يفعل `attome init` ما تفعله البرامج النصية، على جهاز وُضع فيه البرنامج مسبقًا:

```sh
attome init --database-url postgres://postgres:secret@localhost:5432/attome   # يكتب config.json ويطبّق المخطط
attome serve --bootstrap-admin you@example.com                               # مرة واحدة: المسؤول الأول
attome service install --dir /var/lib/attome                                 # خدمة systemd أو خدمة ويندوز
```

يبدأ النشر الجديد بأصغر مجموعة من الوحدات: أساسيات المنصة (السجلات والأشخاص والتدفقات والتدقيق
والإشعارات والبحث والتقارير والمستندات والعروض ولوحات المعلومات) والتطبيق الذي أُنشئ له،
`--app sales` (الافتراضي) أو `--app service` أو `--app both`، مع ما تحتاجه حِزمه في `--pack`.
فعّل غيرها لاحقًا من إدارة الوحدات؛ ويبدأ `--app all` بكل الوحدات.

يطبع `attome service install --dry-run` الخطوات دون تنفيذها. ويعرض `attome sovereignty report` أماكن نسخ
البيانات وكل وجهة خارجية تذكرها الإعدادات.
