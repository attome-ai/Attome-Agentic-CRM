/**
 * Y14-T4: the app designer's own catalogue, registered on its route
 * (`provideLayerCatalog`). Its namespace, `appDesigner`, is owned by this layer only.
 */
export const appDesignerEn = {
  appDesigner: {
    title: 'App designer', apps: 'Apps', newApp: 'New app', noApps: 'No apps yet.',
    version: 'version {{version}}, {{state}}', allApps: 'All apps',
    save: 'Save', publish: 'Publish', saved: 'Draft saved (version {{version}}).', published: 'Published (version {{version}}).',
    nameNeeded: 'Give the app a name in its settings first.',
    conflict: 'Someone saved this app since you opened it. Reload and try again.',
    palette: 'Add to the menu', addGroup: 'Add a group', newGroup: 'Group', firstGroup: 'Main', filter: 'Find…',
    noSources: 'Nothing to add.', byId: 'Add by id or address', kind: 'Opens', idHint: 'Its id', urlHint: 'https://…',
    label: 'Label', add: 'Add',
    kinds: { view: 'View', form: 'Form', dashboard: 'Dashboard', page: 'Page', report: 'Report', flow: 'Flow', url: 'Link' },
    problems: {
      noTarget: '{{item}}: name what it opens by its id.',
      badUrl: '{{item}}: a link starts with https://, http:// or /.',
      duplicate: '{{item}}: the group already has an item with this label.',
    },
    settings: 'Settings', name: 'Name', icon: 'Icon', iconHint: 'las la-briefcase', languages: 'Languages',
    english: 'English', arabic: 'Arabic', timeZone: 'Time zone', timeZoneHint: 'Asia/Riyadh',
    primaryColour: 'Main colour (#rrggbb)', accentColour: 'Accent colour (#rrggbb)',
    simple: 'Simple mode: hide advanced options',
    dependencies: 'What the app uses', map: 'Map it', opens: '{{item}} opens a {{kind}}',
  },
};

export const appDesignerAr = {
  appDesigner: {
    title: 'مصمم التطبيقات', apps: 'التطبيقات', newApp: 'تطبيق جديد', noApps: 'لا تطبيقات بعد.',
    version: 'الإصدار {{version}}، {{state}}', allApps: 'كل التطبيقات',
    save: 'حفظ', publish: 'نشر', saved: 'حُفظت المسودة (الإصدار {{version}}).', published: 'نُشر (الإصدار {{version}}).',
    nameNeeded: 'سمِّ التطبيق في إعداداته أولًا.',
    conflict: 'حفظ شخص آخر هذا التطبيق منذ فتحته. أعد التحميل وحاول مجددًا.',
    palette: 'إضافة إلى القائمة', addGroup: 'إضافة مجموعة', newGroup: 'مجموعة', firstGroup: 'الرئيسية', filter: 'بحث…',
    noSources: 'لا شيء للإضافة.', byId: 'إضافة بالمعرّف أو العنوان', kind: 'يفتح', idHint: 'معرّفه', urlHint: 'https://…',
    label: 'التسمية', add: 'إضافة',
    kinds: { view: 'عرض', form: 'نموذج', dashboard: 'لوحة معلومات', page: 'صفحة', report: 'تقرير', flow: 'تدفق', url: 'رابط' },
    problems: {
      noTarget: '{{item}}: حدّد ما يفتحه بمعرّفه.',
      badUrl: '{{item}}: يبدأ الرابط بـ https:// أو http:// أو /.',
      duplicate: '{{item}}: في المجموعة عنصر بالتسمية نفسها.',
    },
    settings: 'الإعدادات', name: 'الاسم', icon: 'الأيقونة', iconHint: 'las la-briefcase', languages: 'اللغات',
    english: 'الإنجليزية', arabic: 'العربية', timeZone: 'المنطقة الزمنية', timeZoneHint: 'Asia/Riyadh',
    primaryColour: 'اللون الرئيسي (#rrggbb)', accentColour: 'لون التمييز (#rrggbb)',
    simple: 'الوضع البسيط: إخفاء الخيارات المتقدمة',
    dependencies: 'ما يستخدمه التطبيق', map: 'اعرضه', opens: '{{item}} يفتح {{kind}}',
  },
};
