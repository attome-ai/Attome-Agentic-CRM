/**
 * Y14-T4: the report builder's own catalogue, registered on its route
 * (`provideLayerCatalog`), so the xrm catalogue every screen loads no longer
 * carries it. Its namespace, `reportBuilder`, is owned by this layer only.
 */
export const reportBuilderEn = {
  reportBuilder: {
    title: 'Report builder', lead: 'Pick an entity and a layout; the first 50 rows preview as you go. No SQL needed.',
    entity: 'Entity', load: 'Load', layout: 'Layout',
    layouts: { table: 'Table', summary: 'Summary', matrix: 'Matrix' },
    columns: 'Columns', related: 'Related column', relatedHint: 'account.industry', add: 'Add',
    measure: 'Measure', func: 'Show', of: 'of', choose: 'Choose…',
    funcs: { count: 'Count', sum: 'Sum', avg: 'Average', min: 'Lowest', max: 'Highest' },
    rowsBy: 'Rows by', columnsBy: 'Columns by', by: 'By', value: 'Each value',
    buckets: { day: 'Day', week: 'Week', month: 'Month', quarter: 'Quarter', year: 'Year' },
    filters: 'Filters', field: 'Field', operator: 'Operator', valueLabel: 'Value', remove: 'Remove', addFilter: 'Add a filter',
    ops: {
      eq: 'is', neq: 'is not', gt: 'is more than', gte: 'is at least', lt: 'is less than', lte: 'is at most',
      contains: 'contains', is_null: 'is empty', is_not_null: 'is not empty',
    },
    preview: 'Preview', running: 'Running…', live: 'Preview as I change it',
    notReady: 'Choose columns, or a grouping and a measure, to preview.',
    firstRows: '{count, plural, =0 {No rows} one {The first row} other {The first # rows}}',
    total: 'Total', empty: '(empty)',
    prompts: 'Prompts', promptsLead: 'Values asked for each time the report runs.', promptName: 'Parameter name',
    promptType: 'Type', promptValue: 'Value for the preview', addPrompt: 'Add a prompt',
    promptTypes: { text: 'Text', number: 'Number', date: 'Date' },
    chart: 'Chart', noChart: 'No chart',
    charts: { bar: 'Bars', line: 'Line', area: 'Area', donut: 'Donut', funnel: 'Funnel' },
    saveShare: 'Save and share', reportName: 'Report name', saveReport: 'Save the report', savedReport: 'Saved.',
    role: 'Role', team: 'Team', access: 'Access', accessNone: 'Not shared', accessRead: 'Can run it', accessEdit: 'Can run and edit it',
    noPrincipals: 'No roles or teams to share with.', applyShares: 'Save sharing',
    shareSaved: '{count, plural, =0 {Shared with nobody} one {Shared with 1 role or team} other {Shared with # roles or teams}}',
  },
};

export const reportBuilderAr = {
  reportBuilder: {
    title: 'منشئ التقارير', lead: 'اختر كيانًا وتخطيطًا؛ تظهر أول 50 صفًا أثناء العمل. لا حاجة إلى SQL.',
    entity: 'الكيان', load: 'تحميل', layout: 'التخطيط',
    layouts: { table: 'جدول', summary: 'ملخص', matrix: 'مصفوفة' },
    columns: 'الأعمدة', related: 'عمود مرتبط', relatedHint: 'account.industry', add: 'إضافة',
    measure: 'المقياس', func: 'عرض', of: 'لـ', choose: 'اختر…',
    funcs: { count: 'العدد', sum: 'المجموع', avg: 'المتوسط', min: 'الأدنى', max: 'الأعلى' },
    rowsBy: 'الصفوف حسب', columnsBy: 'الأعمدة حسب', by: 'حسب', value: 'كل قيمة',
    buckets: { day: 'اليوم', week: 'الأسبوع', month: 'الشهر', quarter: 'الربع', year: 'السنة' },
    filters: 'عوامل التصفية', field: 'الحقل', operator: 'المعامل', valueLabel: 'القيمة', remove: 'إزالة', addFilter: 'إضافة عامل تصفية',
    ops: {
      eq: 'يساوي', neq: 'لا يساوي', gt: 'أكبر من', gte: 'لا يقل عن', lt: 'أقل من', lte: 'لا يزيد عن',
      contains: 'يحتوي على', is_null: 'فارغ', is_not_null: 'غير فارغ',
    },
    preview: 'معاينة', running: 'جارٍ التشغيل…', live: 'المعاينة أثناء التغيير',
    notReady: 'اختر أعمدة، أو تجميعًا ومقياسًا، للمعاينة.',
    firstRows: '{count, plural, =0 {لا صفوف} one {الصف الأول} two {أول صفين} few {أول # صفوف} other {أول # صفًا}}',
    total: 'الإجمالي', empty: '(فارغ)',
    prompts: 'المطالبات', promptsLead: 'قيم تُطلب في كل مرة يُشغَّل فيها التقرير.', promptName: 'اسم المعامل',
    promptType: 'النوع', promptValue: 'القيمة للمعاينة', addPrompt: 'إضافة مطالبة',
    promptTypes: { text: 'نص', number: 'رقم', date: 'تاريخ' },
    chart: 'المخطط', noChart: 'بلا مخطط',
    charts: { bar: 'أعمدة', line: 'خط', area: 'مساحة', donut: 'حلقة', funnel: 'قمع' },
    saveShare: 'الحفظ والمشاركة', reportName: 'اسم التقرير', saveReport: 'حفظ التقرير', savedReport: 'حُفظ.',
    role: 'دور', team: 'فريق', access: 'الصلاحية', accessNone: 'غير مشارَك', accessRead: 'يمكنه تشغيله', accessEdit: 'يمكنه تشغيله وتعديله',
    noPrincipals: 'لا أدوار أو فرق للمشاركة معها.', applyShares: 'حفظ المشاركة',
    shareSaved: '{count, plural, =0 {غير مشارَك مع أحد} one {مشارَك مع دور أو فريق واحد} two {مشارَك مع اثنين} few {مشارَك مع # أدوار أو فرق} other {مشارَك مع # دورًا أو فريقًا}}',
  },
};
