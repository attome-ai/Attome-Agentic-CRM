/**
 * Y14-T4: the email designer's own catalogue, registered on its route
 * (`provideLayerCatalog`). Its namespace, `emailDesigner`, is owned by this layer only.
 */
export const emailDesignerEn = {
  emailDesigner: {
    title: 'Email designer', working: 'Working…', new: 'New design', none: 'No saved designs yet.',
    name: 'Name', subject: 'Subject', language: 'Language', english: 'English', arabic: 'Arabic',
    width: 'Width (px)', colour: 'Brand colour', colourHint: '#1a56db',
    palette: 'Blocks',
    blocks: {
      heading: 'Heading', text: 'Text', image: 'Image', button: 'Button', divider: 'Divider', spacer: 'Space',
      columns: 'Two columns',
    },
    problems: {
      missingAlt: 'Block {{block}}: an image needs its alt text.',
      badLink: 'Block {{block}}: a link must start with https:, http:, mailto: or tel:, or be a placeholder in double braces.',
      empty: 'Block {{block}}: fill it in or remove it.',
    },
    save: 'Save', saved: 'The design is saved.', nameNeeded: 'Give the design a name first.',
    conflict: 'Someone saved this design since you opened it. Reload and try again.',
    unreadable: 'The saved design could not be read; it opens empty.',
    preview: 'Preview', previewEntity: 'Preview as (entity)', previewPerson: 'Record id',
    render: 'Render', phone: 'Phone width', previewHint: 'Choose a person to see the email as they will get it.',
  },
};

export const emailDesignerAr = {
  emailDesigner: {
    title: 'مصمم البريد الإلكتروني', working: 'جارٍ العمل…', new: 'تصميم جديد', none: 'لا تصاميم محفوظة بعد.',
    name: 'الاسم', subject: 'الموضوع', language: 'اللغة', english: 'الإنجليزية', arabic: 'العربية',
    width: 'العرض (بكسل)', colour: 'لون العلامة', colourHint: '#1a56db',
    palette: 'الكتل',
    blocks: {
      heading: 'عنوان', text: 'نص', image: 'صورة', button: 'زر', divider: 'فاصل', spacer: 'مسافة',
      columns: 'عمودان',
    },
    problems: {
      missingAlt: 'الكتلة {{block}}: تحتاج الصورة إلى نص بديل.',
      badLink: 'الكتلة {{block}}: يجب أن يبدأ الرابط بـ https: أو http: أو mailto: أو tel:، أو أن يكون عنصرًا نائبًا بين قوسين مزدوجين.',
      empty: 'الكتلة {{block}}: املأها أو احذفها.',
    },
    save: 'حفظ', saved: 'حُفظ التصميم.', nameNeeded: 'سمِّ التصميم أولًا.',
    conflict: 'حفظ شخص آخر هذا التصميم منذ فتحته. أعد التحميل وحاول مجددًا.',
    unreadable: 'تعذّرت قراءة التصميم المحفوظ؛ فُتح فارغًا.',
    preview: 'معاينة', previewEntity: 'المعاينة باسم (الكيان)', previewPerson: 'معرّف السجل',
    render: 'عرض', phone: 'عرض الهاتف', previewHint: 'اختر شخصًا لترى البريد كما سيصله.',
  },
};
