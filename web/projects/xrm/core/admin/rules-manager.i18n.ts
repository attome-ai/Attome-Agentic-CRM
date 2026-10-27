/**
 * Y14-T4: the business rules manager's own catalogue, registered on its route
 * (`provideLayerCatalog`). Its namespaces, `businessRules`, are owned by this layer only.
 */
export const businessRulesEn = {
  businessRules: {
    title: 'Business rules',
    intro: 'Hide or lock fields, show errors and set values when a condition holds, for all users or for chosen roles. The server enforces every rule on every write.',
    action: {
      new: 'New rule', close: 'Close', reload: 'Reload', save: 'Save', saving: 'Saving…',
      validate: 'Validate', validating: 'Validating…', publish: 'Publish', publishing: 'Publishing…',
      retire: 'Retire', cancel: 'Cancel',
    },
    list: {
      entityFilter: 'Entity', allEntities: 'All entities', search: 'Filter by name or entity',
      count: '{count, plural, one {# rule} other {# rules}}', loading: 'Loading rules…',
      appliesToNobody: 'Applies to nobody', turnedOff: 'Turned off by a release', loadError: 'Cannot be read',
      empty: 'No rules match.', pick: 'Select a rule to edit, or create a new one.', nobody: 'No live role',
      hides: '{count, plural, one {hides # field} other {hides # fields}}',
      locks: '{count, plural, one {locks # field} other {locks # fields}}',
      errors: '{count, plural, one {# error} other {# errors}}',
      sets: '{count, plural, one {sets # value} other {sets # values}}',
      noPolicies: 'No policies',
    },
    badge: {
      legacy: 'Legacy ({kind})', inactive: 'Inactive',
      version: 'Version {version}',
    },
    editor: {
      newTitle: 'New business rule', editTitle: 'Edit business rule',
      turnedOff: 'A release turned this rule off ({reason}). Fix it and turn it back on.',
      appliesToNobody: 'This rule names roles, but none of them exists any more, so it applies to nobody.',
      loadError: 'The stored rule cannot be read and is not enforced: {reason}',
      conflict: 'Someone else changed this rule. Reload to see the latest version; your unsaved changes will be lost.',
      entity: 'Entity', name: 'Name', displayName: 'Display name', displayOrder: 'Order',
      description: 'Description', active: 'Active', pickEntity: 'Choose an entity',
      attributesFailed: 'The fields of this entity could not be loaded.',
    },
    legacy: {
      targetField: 'Target field', severity: 'Severity', expression: 'Expression', message: 'Message',
    },
    severity: { error: 'Error (blocks the save)', warning: 'Warning (saves, shows the message)' },
    audience: {
      title: 'Applies to', all: 'All users', roles: 'Selected roles', staffRoles: 'Staff roles',
      noStaffRoles: 'No staff roles yet.', portalRoles: 'Portal roles: {portal}',
    },
    condition: {
      title: 'When', group: 'Group', matchLabel: 'How the conditions combine',
      matchAll: 'All of these', matchAny: 'Any of these', removeGroup: 'Remove group',
      always: 'Always (no conditions).', field: 'Field', operator: 'Operator', values: 'Values',
      valuesOnePerLine: 'One value per line', value: 'Value', yes: 'Yes', no: 'No',
      pickValue: 'Choose a value', recordId: 'Record id', removeCondition: 'Remove condition',
      advanced: 'Advanced', advancedLabel: 'Advanced expression',
      advancedPlaceholder: 'e.g. amount > discount * 2',
      advancedHint: 'An advanced expression is evaluated on the server only, so a rule that has one cannot hide or lock fields.',
      addCondition: 'Add condition', addGroup: 'Add group', addAdvanced: 'Add advanced expression',
    },
    op: {
      eq: 'equals', ne: 'does not equal', gt: 'is greater than', gte: 'is at least',
      lt: 'is less than', lte: 'is at most', in: 'is one of', not_in: 'is not one of',
      contains: 'contains', starts_with: 'starts with', is_empty: 'is empty', is_not_empty: 'is not empty',
    },
    field: {
      sensitive: '{name} (sensitive)', owner_ref: 'Owner', organization_ref: 'Organization',
    },
    policy: {
      title: 'Then', hint: 'Policies apply in this order when the condition holds.',
      type: 'Policy', field: 'Field', noField: 'No field (the whole record)',
      moveUp: 'Move up', moveDown: 'Move down', remove: 'Remove policy',
      message: 'Message', severity: 'Severity', source: 'Value source', literal: 'Fixed value',
      expression: 'Expression', value: 'Value', mode: 'When',
      modeAlways: 'On every save', modeDefault: 'On create, when empty',
      empty: 'No policies yet.',
      types: { hidden: 'Hide field', disabled: 'Lock field', error: 'Show error', set_value: 'Set value' },
      add: { hidden: 'Hide field', disabled: 'Lock field', error: 'Show error', set_value: 'Set value' },
      summary: {
        hidden: 'Hide {field}', disabled: 'Lock {field}', error: 'Show an error on {field}', set_value: 'Set {field}',
      },
    },
    issue: {
      lockWithAdvanced: 'A rule with an advanced expression cannot hide or lock fields. Remove the expression or those policies.',
      noRoles: 'Choose at least one role, or apply the rule to all users.',
      noPolicies: 'Add at least one policy.',
    },
    notice: {
      saved: 'Rule saved. Publish it to record this version.',
      published: 'Published as version {version}.',
      valid: 'The rule is valid.',
    },
    warning: {
      required_field_locked: '{field} is required: users this rule locks it for cannot save a record while it is empty.',
      rule_applies_to_admins: 'This rule also restricts administrators.',
      no_matching_users: 'No user holds the chosen roles.',
      set_value_conflict: 'Another active rule also sets {field}; the later rule wins.',
      locks_everyone: 'This rule always locks fields for every user.',
    },
    test: {
      title: 'Test', hint: 'Evaluates the SAVED rule against a sample record. Nothing is saved.',
      audience: 'Test as', portalRole: 'Portal role', pickRole: 'Choose a role', staffRoles: 'Roles held',
      record: 'Sample record (JSON)', run: 'Run test', running: 'Running…',
      badJson: 'The sample record must be a JSON object.',
      applies: 'Applies:', condition: 'Condition:', fired: 'Policies that fire:',
      trace: 'Trace ({count} steps)',
      mode: {
        unscoped: 'Anyone (ignore the audience)', staff: 'A staff user with roles', portal: 'A portal user',
        integration: 'An integration (API key or S2S)', system: 'A system process',
      },
      outcome: { true: 'true', false: 'false', unknown: 'unknown (treated as true)', transient: 'busy, try again' },
    },
  },
};

export const businessRulesAr = {
  businessRules: {
    title: 'قواعد العمل',
    intro: 'أخفِ الحقول أو اقفلها، واعرض الأخطاء، وعيّن القيم عند تحقق شرط، لجميع المستخدمين أو لأدوار محددة. يفرض الخادم كل قاعدة عند كل حفظ.',
    action: {
      new: 'قاعدة جديدة', close: 'إغلاق', reload: 'إعادة التحميل', save: 'حفظ', saving: 'جارٍ الحفظ…',
      validate: 'تحقق', validating: 'جارٍ التحقق…', publish: 'نشر', publishing: 'جارٍ النشر…',
      retire: 'إيقاف', cancel: 'إلغاء',
    },
    list: {
      entityFilter: 'الكيان', allEntities: 'كل الكيانات', search: 'تصفية بالاسم أو الكيان',
      count: '{count, plural, one {قاعدة واحدة} other {# قواعد}}', loading: 'جارٍ تحميل القواعد…',
      appliesToNobody: 'لا تنطبق على أحد', turnedOff: 'أوقفها إصدار', loadError: 'تتعذر قراءتها',
      empty: 'لا توجد قواعد مطابقة.', pick: 'اختر قاعدة لتحريرها، أو أنشئ قاعدة جديدة.', nobody: 'لا يوجد دور قائم',
      hides: '{count, plural, one {تخفي حقلًا واحدًا} other {تخفي # حقول}}',
      locks: '{count, plural, one {تقفل حقلًا واحدًا} other {تقفل # حقول}}',
      errors: '{count, plural, one {خطأ واحد} other {# أخطاء}}',
      sets: '{count, plural, one {تعيّن قيمة واحدة} other {تعيّن # قيم}}',
      noPolicies: 'لا توجد سياسات',
    },
    badge: {
      legacy: 'قديمة ({kind})', inactive: 'غير نشطة',
      version: 'الإصدار {version}',
    },
    editor: {
      newTitle: 'قاعدة عمل جديدة', editTitle: 'تحرير قاعدة عمل',
      turnedOff: 'أوقف إصدارٌ هذه القاعدة ({reason}). أصلحها ثم أعد تشغيلها.',
      appliesToNobody: 'تحدد هذه القاعدة أدوارًا لم يعد أي منها موجودًا، لذا لا تنطبق على أحد.',
      loadError: 'تتعذر قراءة القاعدة المخزنة ولا تُفرض: {reason}',
      conflict: 'غيّر شخص آخر هذه القاعدة. أعد التحميل لرؤية أحدث إصدار؛ ستفقد تغييراتك غير المحفوظة.',
      entity: 'الكيان', name: 'الاسم', displayName: 'اسم العرض', displayOrder: 'الترتيب',
      description: 'الوصف', active: 'نشطة', pickEntity: 'اختر كيانًا',
      attributesFailed: 'تعذر تحميل حقول هذا الكيان.',
    },
    legacy: {
      targetField: 'الحقل المستهدف', severity: 'الخطورة', expression: 'التعبير', message: 'الرسالة',
    },
    severity: { error: 'خطأ (يمنع الحفظ)', warning: 'تحذير (يحفظ ويعرض الرسالة)' },
    audience: {
      title: 'تنطبق على', all: 'جميع المستخدمين', roles: 'أدوار محددة', staffRoles: 'أدوار الموظفين',
      noStaffRoles: 'لا توجد أدوار موظفين بعد.', portalRoles: 'أدوار البوابة: {portal}',
    },
    condition: {
      title: 'عندما', group: 'مجموعة', matchLabel: 'كيفية جمع الشروط',
      matchAll: 'كل هذه الشروط', matchAny: 'أي من هذه الشروط', removeGroup: 'إزالة المجموعة',
      always: 'دائمًا (بلا شروط).', field: 'الحقل', operator: 'العامل', values: 'القيم',
      valuesOnePerLine: 'قيمة واحدة في كل سطر', value: 'القيمة', yes: 'نعم', no: 'لا',
      pickValue: 'اختر قيمة', recordId: 'معرّف السجل', removeCondition: 'إزالة الشرط',
      advanced: 'متقدم', advancedLabel: 'تعبير متقدم',
      advancedPlaceholder: 'مثال: amount > discount * 2',
      advancedHint: 'يُقيَّم التعبير المتقدم على الخادم فقط، لذا لا يمكن لقاعدة تحتوي عليه أن تخفي الحقول أو تقفلها.',
      addCondition: 'إضافة شرط', addGroup: 'إضافة مجموعة', addAdvanced: 'إضافة تعبير متقدم',
    },
    op: {
      eq: 'يساوي', ne: 'لا يساوي', gt: 'أكبر من', gte: 'لا يقل عن',
      lt: 'أصغر من', lte: 'لا يزيد على', in: 'أحد', not_in: 'ليس أحد',
      contains: 'يحتوي على', starts_with: 'يبدأ بـ', is_empty: 'فارغ', is_not_empty: 'غير فارغ',
    },
    field: {
      sensitive: '{name} (حساس)', owner_ref: 'المالك', organization_ref: 'المؤسسة',
    },
    policy: {
      title: 'عندئذٍ', hint: 'تُطبَّق السياسات بهذا الترتيب عند تحقق الشرط.',
      type: 'السياسة', field: 'الحقل', noField: 'بلا حقل (السجل كله)',
      moveUp: 'نقل لأعلى', moveDown: 'نقل لأسفل', remove: 'إزالة السياسة',
      message: 'الرسالة', severity: 'الخطورة', source: 'مصدر القيمة', literal: 'قيمة ثابتة',
      expression: 'تعبير', value: 'القيمة', mode: 'متى',
      modeAlways: 'عند كل حفظ', modeDefault: 'عند الإنشاء، إذا كان فارغًا',
      empty: 'لا توجد سياسات بعد.',
      types: { hidden: 'إخفاء حقل', disabled: 'قفل حقل', error: 'عرض خطأ', set_value: 'تعيين قيمة' },
      add: { hidden: 'إخفاء حقل', disabled: 'قفل حقل', error: 'عرض خطأ', set_value: 'تعيين قيمة' },
      summary: {
        hidden: 'إخفاء {field}', disabled: 'قفل {field}', error: 'عرض خطأ على {field}', set_value: 'تعيين {field}',
      },
    },
    issue: {
      lockWithAdvanced: 'لا يمكن لقاعدة تحتوي على تعبير متقدم أن تخفي الحقول أو تقفلها. أزل التعبير أو تلك السياسات.',
      noRoles: 'اختر دورًا واحدًا على الأقل، أو طبّق القاعدة على جميع المستخدمين.',
      noPolicies: 'أضف سياسة واحدة على الأقل.',
    },
    notice: {
      saved: 'حُفظت القاعدة. انشرها لتسجيل هذا الإصدار.',
      published: 'نُشرت بالإصدار {version}.',
      valid: 'القاعدة صالحة.',
    },
    warning: {
      required_field_locked: '{field} مطلوب: لا يستطيع المستخدمون الذين تقفله القاعدة لهم حفظ سجل وهو فارغ.',
      rule_applies_to_admins: 'تقيّد هذه القاعدة المسؤولين أيضًا.',
      no_matching_users: 'لا يحمل أي مستخدم الأدوار المختارة.',
      set_value_conflict: 'قاعدة نشطة أخرى تعيّن {field} أيضًا؛ القاعدة اللاحقة هي التي تسري.',
      locks_everyone: 'تقفل هذه القاعدة الحقول دائمًا لكل المستخدمين.',
    },
    test: {
      title: 'اختبار', hint: 'يقيّم القاعدة المحفوظة على سجل نموذجي. لا يُحفظ شيء.',
      audience: 'الاختبار بصفة', portalRole: 'دور البوابة', pickRole: 'اختر دورًا', staffRoles: 'الأدوار المملوكة',
      record: 'سجل نموذجي (JSON)', run: 'تشغيل الاختبار', running: 'جارٍ التشغيل…',
      badJson: 'يجب أن يكون السجل النموذجي كائن JSON.',
      applies: 'تنطبق:', condition: 'الشرط:', fired: 'السياسات المطبقة:',
      trace: 'التتبع ({count} خطوات)',
      mode: {
        unscoped: 'أي شخص (تجاهل الجمهور)', staff: 'موظف بأدوار', portal: 'مستخدم بوابة',
        integration: 'تكامل (مفتاح API أو S2S)', system: 'عملية نظام',
      },
      outcome: { true: 'صحيح', false: 'خطأ', unknown: 'غير معروف (يُعامل كصحيح)', transient: 'مشغول، أعد المحاولة' },
    },
  },
};
