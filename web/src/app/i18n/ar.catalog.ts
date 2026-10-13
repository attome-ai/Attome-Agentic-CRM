// Arabic catalog for the host app — mirrors en.catalog.ts key-for-key
// (NGB-5.2b, D-761). Loaded on first use, never in `main`.

export const hostAr = {
  authModal: {
    googleError: 'فشل تسجيل الدخول باستخدام جوجل.',
    dialogAriaLabel: 'تسجيل الدخول إلى أتوم',
    closeAriaLabel:  'إغلاق',
  },
  // See en.catalog.ts's note — referenced by the host app's XRM login page,
  // previously missing from both catalogs.
  xrmLogin: {
    invalidCredentials: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.',
    invalidCode:        'الرمز غير صحيح أو انتهت صلاحيته. يرجى المحاولة مرة أخرى.',
    googleError:        'فشل تسجيل الدخول عبر Google. يرجى المحاولة مرة أخرى.',
  },
  securitySettings: {
    googleLinkConflict: 'حساب Google هذا مرتبط بالفعل بمستخدم آخر.',
    googleLinkError: 'فشل الربط. يرجى المحاولة مرة أخرى.',
    stepUpComplete: 'تم تأكيد هويتك. يمكنك المتابعة الآن.',
    stepUpError: 'تعذّر تأكيد هويتك. لم يتم تغيير أي شيء.',
    stepUpExpired: 'لم يعد تأكيد هويتك صالحاً. يرجى المحاولة مرة أخرى.',
    stepUpCheckFailed: 'تعذّر التحقق من تأكيد هويتك. يرجى المحاولة مرة أخرى.',
    apiKey: {
      title: 'مفاتيح API',
      subtitle: 'أنشئ مفتاحاً للبرامج النصية والتكاملات التي تستدعي الواجهة البرمجية باسمك.',
      nameLabel: 'اسم المفتاح',
      expiryLabel: 'تنتهي صلاحيته بعد (أيام، اختياري)',
      create: 'إنشاء مفتاح API', creating: 'جاري الإنشاء…',
      nameRequired: 'أدخل اسماً للمفتاح.',
      expiryInvalid: 'أدخل عدداً صحيحاً من الأيام أكبر من صفر، أو اتركه فارغاً.',
      notCreated: 'لم يتم إنشاء مفتاح API.',
      ready: 'تم تأكيد هويتك. أنشئ مفتاح API الآن.',
      createdTitle: 'تم إنشاء مفتاح API',
      copyNow: 'انسخ هذا السر الآن. لن يُعرض مرة أخرى.',
      publicKeyLabel: 'معرّف المفتاح', secretLabel: 'السر',
      dismiss: 'لقد نسخته',
    },
  },
  register: {
    emailTaken: 'البريد الإلكتروني مسجل بالفعل.',
    invalidInvitation: 'رمز الدعوة هذا غير صالح أو منتهي الصلاحية أو تم استخدامه بالفعل.',
  },
};
