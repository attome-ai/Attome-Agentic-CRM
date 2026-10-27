/**
 * Y14-T4: the agent designer's own catalogue, registered on its route
 * (`provideLayerCatalog`). Its namespaces, `agentDesigner`, are owned by this layer only.
 */
export const agentDesignerEn = {
  agentDesigner: {
    title: 'Agents', agents: 'Agents', new: 'New agent', none: 'No agents yet.',
    name: 'Name', role: 'Role', instructions: 'Instructions', tools: 'Tools', limits: 'Limits',
    maxSteps: 'Most steps', maxToolCalls: 'Most tool calls', maxTokens: 'Most tokens',
    runAs: 'Runs as', runAsCaller: 'The person using it', runAsService: 'Its own service identity',
    channels: 'Channels', save: 'Save draft', publish: 'Publish', saved: 'Draft saved', published: 'Published',
    channel: { chat: 'Chat', web: 'Web', whatsapp: 'WhatsApp', sms: 'SMS', email: 'Email' },
    usage: 'Used today', noLimit: 'no limit',
    dailyHint: 'Per day, across all of this agent\'s sessions. Leave blank for no limit.',
    daily: { record_changes: 'Records changed', deletes: 'Deletes', messages: 'Messages sent', external_calls: 'Outside calls' },
    policy: 'Agent policy id', model: 'AI model id', language: 'Answer language', languageAny: 'The person\'s language',
    runtimeHint: 'With a policy and a model, sessions can start from this agent itself once it is published.',
    tests: 'Tests', showTests: 'Show tests', noSuites: 'No eval suites test this agent yet.', runTests: 'Run', casePassed: 'passed',
    runStatus: { running: 'Running…', passed: 'Passed', failed: 'Failed', error: 'Could not run' },
    handoff: 'Delegated work', handoffOn: 'Other agents can delegate to this one',
    handoffHint: 'The input this agent takes and the answer it gives, as JSON Schema objects. Delegated work only reads.',
    handoffInput: 'Input contract', handoffOutput: 'Output contract',
    handoffInvalid: { input: 'The input contract is not a JSON object.', output: 'The output contract is not a JSON object.' },
  },
};

export const agentDesignerAr = {
  agentDesigner: {
    title: 'الوكلاء', agents: 'الوكلاء', new: 'وكيل جديد', none: 'لا يوجد وكلاء بعد.',
    name: 'الاسم', role: 'الدور', instructions: 'التعليمات', tools: 'الأدوات', limits: 'الحدود',
    maxSteps: 'أقصى عدد من الخطوات', maxToolCalls: 'أقصى عدد من استدعاءات الأدوات', maxTokens: 'أقصى عدد من الرموز',
    runAs: 'يعمل بصفة', runAsCaller: 'الشخص الذي يستخدمه', runAsService: 'هوية الخدمة الخاصة به',
    channels: 'القنوات', save: 'حفظ المسودة', publish: 'نشر', saved: 'تم حفظ المسودة', published: 'تم النشر',
    channel: { chat: 'المحادثة', web: 'الويب', whatsapp: 'واتساب', sms: 'الرسائل النصية', email: 'البريد الإلكتروني' },
    usage: 'المستخدم اليوم', noLimit: 'بلا حد',
    dailyHint: 'في اليوم، عبر جميع جلسات هذا الوكيل. اتركه فارغًا لعدم وجود حد.',
    daily: { record_changes: 'السجلات المعدّلة', deletes: 'عمليات الحذف', messages: 'الرسائل المرسلة', external_calls: 'الاستدعاءات الخارجية' },
    policy: 'معرّف سياسة الوكيل', model: 'معرّف نموذج الذكاء الاصطناعي', language: 'لغة الإجابة', languageAny: 'لغة الشخص',
    runtimeHint: 'مع سياسة ونموذج، يمكن بدء الجلسات من هذا الوكيل نفسه بعد نشره.',
    tests: 'الاختبارات', showTests: 'عرض الاختبارات', noSuites: 'لا توجد مجموعات تقييم تختبر هذا الوكيل بعد.', runTests: 'تشغيل', casePassed: 'نجح',
    runStatus: { running: 'قيد التشغيل…', passed: 'نجح', failed: 'فشل', error: 'تعذّر التشغيل' },
    handoff: 'العمل المفوَّض', handoffOn: 'يمكن للوكلاء الآخرين تفويض العمل لهذا الوكيل',
    handoffHint: 'المدخلات التي يأخذها هذا الوكيل والإجابة التي يعيدها، ككائنات JSON Schema. العمل المفوَّض للقراءة فقط.',
    handoffInput: 'عقد المدخلات', handoffOutput: 'عقد المخرجات',
    handoffInvalid: { input: 'عقد المدخلات ليس كائن JSON.', output: 'عقد المخرجات ليس كائن JSON.' },
  },
};
