# تسجيل الدخول بمزوّد هوية SAML عبر وسيط

يسجّل Attome دخول الأشخاص بواسطة **OpenID Connect فقط**. لا توجد فيه نقطة نهاية SAML: لا يستقبل
تأكيد SAML أبدًا ولا ينشر بيانات تعريف SAML. فإذا كان مزوّد الهوية لدى العميل لا يدعم إلا SAML،
يُوضع **وسيط هوية** بين الطرفين: يثق الوسيط بمزوّد SAML، ويثق Attome بالوسيط عبر OpenID Connect.

```
الشخص ──▶ Attome ──OIDC──▶ الوسيط (Entra ID أو Okta أو AD FS أو Keycloak) ──SAML──▶ مزوّد هوية العميل
```

تسجيل الخروج الموحّد عبر الوسيط غير مصمَّم: الخروج من Attome ينهي جلسة Attome فقط، والخروج من
مزوّد SAML لا ينهيها.

## ما يحتاجه كل وسيط

**عنوان إعادة التوجيه.** سجّله كما هو تمامًا:

```
https://<your-attome-host>/api/v1/auth/oidc/<provider>/callback
```

`<provider>` هو المفتاح الذي تختاره للوسيط في إعدادات Attome (`entra` أو `okta` أو `adfs` أو
`keycloak` ...)، ويجب أن يتطابق في الطرفين.

**المطالبات (Claims).** يقرأ Attome من رمز الهوية (ID token):

| المطالبة | الغرض |
|---|---|
| `sub` | هوية الشخص لدى الوسيط، وتُربط بحسابه في Attome |
| `email` (أو المطالبة التي يسمّيها `email_claim`) | تطابق حساب الشخص في Attome بالبريد عند أول دخول، أو تنشئه (يلزم مقعد ترخيص) |
| `email_verified` | مطلوبة افتراضيًا؛ المزوّد الذي لا يرسلها يحتاج `"require_email_verified_claim": false`، وذلك فقط إن كنت تثق بقيم البريد لديه |
| `amr` أو `acr` | تحتسب الدخول متعدد العوامل لدى المزوّد عاملًا متعددًا في Attome (انظر أدناه) |
| `auth_time` | حداثة تسجيل الدخول، لأجل التحقق المعزّز |

لا يقرأ Attome اليوم مطالبتي `name` و`groups`: الأسماء والأدوار تُدار داخل Attome. ولا ضرر من
إرسالهما.

**إعدادات Attome.** في `config.json` ضمن `oidc.providers` (الأسرار تأتي من متغيرات البيئة، لا من
الملف):

```json
"oidc": {
  "providers": {
    "keycloak": {
      "display_name": "دخول الشركة",
      "issuer": "https://sso.example.com/realms/attome",
      "client_id": "attome",
      "client_secret": "${OIDC_KEYCLOAK_SECRET}",
      "scopes": ["openid", "email", "profile"],
      "mfa_acr_values": ["mfa"],
      "trust_idp_mfa": true
    }
  }
}
```

لا ينتهي `issuer` بشرطة مائلة، ويجب أن يستجيب `<issuer>/.well-known/openid-configuration`. أعد
تشغيل Attome بعد التغيير، فيظهر زر المزوّد في صفحة الدخول.

**التحقق متعدد العوامل والتحقق المعزّز.** إذا كان `trust_idp_mfa` صحيحًا وكانت `amr` في رمز الهوية
تحتوي إحدى قيم `mfa_acr_values` أو كانت `acr` تساويها، يُحتسب الدخول متعدد العوامل، فتُستوفى السياسة
التي تشترطه دون عامل Attome الخاص. وعند إجراء حسّاس يطلب Attome دخولًا جديدًا (تحقق معزّز): يرسل إلى
الوسيط `prompt=login` و`max_age`، ولا يقبل إلا رمزًا حديث `auth_time`. ويجب أن ينقل الوسيط ذلك إلى
مزوّد SAML على شكل مصادقة إلزامية (`ForceAuthn`)؛ فالوسيط الذي يكتفي بإعادة فحص جلسته يثبت دخولًا
جديدًا لديه هو، لا لدى مزوّد SAML.

## Microsoft Entra ID

استخدمه حين يكون مزوّد SAML مربوطًا بـ Entra ID (الهويات الخارجية، اتحاد مزوّد هوية SAML/WS-Fed)
أو حين يكون Entra ID نفسه دليل الشركة.

1. **App registrations ← New registration**: منصة *Web* بعنوان إعادة التوجيه أعلاه
   (`<provider>` = `entra`).
2. **Certificates & secrets**: أضف سرّ عميل وضعه في متغيرات البيئة.
3. **Token configuration**: أضف المطالبتين الاختياريتين `email`، و`upn` للمستخدمين بلا صندوق بريد
   (واضبط حينها `email_claim` على `upn`).
4. لا يرسل Entra ID مطالبة `email_verified`: اضبط `"require_email_verified_claim": false` فقط لمستأجر
   تثق بقيم البريد فيه.
5. للتحقق متعدد العوامل يضع Entra ID القيمة `mfa` في `amr`: `"mfa_acr_values": ["mfa"]`.
6. المُصدِر: `https://login.microsoftonline.com/<tenant-id>/v2.0`.
7. التحقق المعزّز: يحترم Entra ID القيمة `prompt=login`، ويمرّر دخولًا إلزاميًا إلى مزوّد SAML المربوط.

## Okta

1. **Security ← Identity Providers ← Add identity provider ← SAML 2.0**: استورد بيانات تعريف مزوّد
   العميل، واربط `NameID` أو سمة البريد باسم مستخدم Okta، وأضف قاعدة توجيه ترسل نطاق العميل إليه.
2. **Applications ← Create App Integration ← OIDC ← Web Application**: عنوان إعادة التوجيه كما أعلاه
   (`<provider>` = `okta`)، ونوع المنح *Authorization Code*.
3. أسند الأشخاص أو المجموعات المسموح لهم باستخدام Attome.
4. المُصدِر: `https://<your-org>.okta.com` (خادم تفويض المؤسسة) أو
   `https://<your-org>.okta.com/oauth2/default`.
5. يرسل Okta المطالبة `email_verified`، ويضع `mfa` في `amr` عند التحقق متعدد العوامل:
   `"mfa_acr_values": ["mfa"]`.
6. التحقق المعزّز: يحترم Okta القيمة `prompt=login`؛ فعّل *Force authentication* في إعدادات مزوّد SAML
   كي يطلب مزوّد العميل الدخول من جديد.

## AD FS (إصدار 2016 فأحدث)

يدعم AD FS بروتوكول OpenID Connect عبر مجموعة تطبيقات، ويمكنه أن يثق بنفسه بمزوّد مطالبات SAML.

1. **Claims Provider Trusts**: أضف مزوّد SAML لدى العميل (إن لم يكن AD FS هو المزوّد نفسه).
2. **Application Groups ← Add ← Server application accessing a web API**: عنوان إعادة التوجيه كما أعلاه
   (`<provider>` = `adfs`)، وأنشئ سرًّا مشتركًا.
3. في جزء واجهة الويب، امنح `openid` و`email` و`profile`، وأضف قاعدة إصدار ترسل `email` (من
   *E-Mail-Addresses*).
4. لا يرسل AD FS المطالبة `email_verified`: اضبط `"require_email_verified_claim": false` إن كنت تثق
   بقيم البريد في الدليل.
5. للتحقق متعدد العوامل يضع AD FS القيمة `http://schemas.microsoft.com/claims/multipleauthn` في `amr`:
   `"mfa_acr_values": ["http://schemas.microsoft.com/claims/multipleauthn"]`.
6. المُصدِر: `https://<adfs-host>/adfs`.
7. التحقق المعزّز: يحترم AD FS القيمة `prompt=login`، ويمرّر دخولًا إلزاميًا إلى مزوّد مطالبات SAML
   الموثوق.

## Keycloak

1. في النطاق (Realm): **Identity providers ← SAML v2.0**: استورد بيانات تعريف مزوّد العميل (أو رابط
   الوصف)، واضبط تدفق أول دخول عبر الوسيط، وفعّل *Force authentication* إن كان يجب أن يصل كل تحقق
   معزّز إلى مزوّد SAML، واربط سمة البريد بـ `email` وعلّمها موثّقة (*Trust email*) حين تثق بقيم البريد
   لدى المزوّد.
2. **Clients ← Create client ← OpenID Connect**: معرّف العميل `attome`، و*Client authentication*
   مفعّل، و*Standard flow* مفعّل، وعنوان إعادة التوجيه المسموح كما أعلاه (`<provider>` = `keycloak`)،
   وانسخ السرّ من *Credentials*.
3. للتحقق متعدد العوامل اربط مستوى مصادقة بقيمة `acr` في *ACR to LoA mapping* الخاصة بالعميل (مثلًا
   `mfa` ← 2)، واضبط `"mfa_acr_values": ["mfa"]`.
4. المُصدِر: `https://<keycloak-host>/realms/<realm>`.

### تشغيل Keycloak بوصفه الوسيط

Keycloak خدمة مستقلة يشغّلها العميل ويحدّثها بنفسه؛ لا يوزّعها Attome ولا يشغّلها ولا يرقّيها.

- **تشغيلًا مباشرًا** (Java 21 على ويندوز أو لينكس): فكّ حزمة Keycloak ثم
  ```
  bin/kc.sh start --hostname=https://sso.example.com --https-certificate-file=... --https-certificate-key-file=...
  ```
  (`bin\kc.bat` على ويندوز). شغّله خدمةً بمدير خدمات النظام (systemd على لينكس، وغلاف خدمة ويندوز على
  ويندوز)، بقاعدة بيانات PostgreSQL خاصة به (`--db=postgres --db-url=...`) لا بقاعدة Attome.
- **داخل حاوية**:
  ```
  docker run -p 8443:8443 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=... \
    quay.io/keycloak/keycloak:26.0 start --hostname=https://sso.example.com
  ```
- **استيراد نطاق** مُعدّ مسبقًا: `bin/kc.sh import --file realm.json` (والخادم متوقف)، أو
  *Realm settings ← Partial import* من لوحة الإدارة.

ثم أضف مزوّد SAML لدى العميل وعميل Attome كما سبق، ووجّه `oidc.providers.keycloak.issuer` إلى النطاق.

## التحقق من الإعداد

1. افتح صفحة دخول Attome: يظهر زر المزوّد باسم `display_name`.
2. سجّل الدخول: يرسلك الوسيط إلى مزوّد SAML ثم يعيدك إلى `/api/v1/auth/oidc/<provider>/callback`.
3. إن رفض Attome الدخول، فتأكد أن رمز الهوية يحمل `email` (و`email_verified` ما لم تعطّلها)، وأن
   المُصدِر يطابق تمامًا، وأن عنوان إعادة التوجيه متطابق في الطرفين.
