/**
 * Y14-T4: the agent sessions screen's own catalogue, registered on its route
 * (`provideLayerCatalog`). Its namespaces, `agentSessions`, are owned by this layer only.
 */
export const agentSessionsEn = {
  agentSessions: {
    retrievalModeNotice: 'The same applies to knowledge retrieval: each session keeps the retrieval mode it started with. Editing the agent changes new sessions only.',
    colRetrieval: 'Knowledge retrieval', colRetrievalNote: 'the mode this session uses',
    modeToolInvoked: 'Tool-invoked', modePreRetrieved: 'Pre-retrieved', modeUnrecognised: 'Unrecognised value',
    modeStored: 'stored at start',
    modeConfigured: 'agent now: {mode}',
    modeDiffers: 'differs — applies to new sessions only',
    trace: 'Steps', traceTitle: 'What this session did', traceEmpty: 'This session has not invoked anything yet.',
    // AH1-T6 — undoing what a session wrote.
    undo: {
      button: 'Undo run', title: 'Undo what this session did', loading: 'Working out what can be undone…',
      nothing: 'This session changed nothing that can be undone.',
      restore: 'Will be put back', skipped: 'Skipped: a person changed these since', impossible: 'Cannot be undone',
      confirm: 'Undo now', cancel: 'Cancel',
      restoredCount: '{count} put back', skippedCount: '{count} skipped', failedCount: '{count} failed',
      step: { revert_fields: 'values set back', soft_delete: 'moved to the recycle bin', restore: 'restored' },
      status: { planned: 'Planned', running: 'Undoing…', done: 'Done', failed: 'Finished with failures' },
    },
    // AH2-T5 — rolling an agent back to a time.
    rollback: {
      button: 'Roll back agent since…', title: 'Roll back this agent',
      lede: 'Stops the agent\'s live sessions, then undoes what all its sessions did since the time below, newest first. A record a person changed since is left as it is.',
      since: 'Since', sessions: '{count} session(s) since then', confirm: 'Stop and roll back',
    },
  },

};

export const agentSessionsAr = {
  agentSessions: {
    retrievalModeNotice: 'ينطبق الأمر نفسه على استرجاع المعرفة: تحتفظ كل جلسة بوضع الاسترجاع الذي بدأت به. تعديل الوكيل يغيّر الجلسات الجديدة فقط.',
    colRetrieval: 'استرجاع المعرفة', colRetrievalNote: 'الوضع الذي تستخدمه هذه الجلسة',
    modeToolInvoked: 'عند الاستدعاء', modePreRetrieved: 'استرجاع مسبق', modeUnrecognised: 'قيمة غير معروفة',
    modeStored: 'مخزن عند البدء',
    modeConfigured: 'الوكيل الآن: {mode}',
    modeDiffers: 'مختلف — ينطبق على الجلسات الجديدة فقط',
    trace: 'الخطوات', traceTitle: 'ما الذي فعلته هذه الجلسة', traceEmpty: 'لم تستدعِ هذه الجلسة شيئًا بعد.',
    // AH1-T6 — التراجع عمّا كتبته الجلسة.
    undo: {
      button: 'تراجع عن التشغيل', title: 'التراجع عمّا فعلته هذه الجلسة', loading: 'جارٍ تحديد ما يمكن التراجع عنه…',
      nothing: 'لم تغيّر هذه الجلسة شيئًا يمكن التراجع عنه.',
      restore: 'سيُعاد كما كان', skipped: 'تم تخطّيه: غيّره شخص بعد ذلك', impossible: 'لا يمكن التراجع عنه',
      confirm: 'تراجع الآن', cancel: 'إلغاء',
      restoredCount: 'أُعيد {count}', skippedCount: 'تُخطّي {count}', failedCount: 'فشل {count}',
      step: { revert_fields: 'أُعيدت القيم', soft_delete: 'نُقل إلى سلة المحذوفات', restore: 'استُعيد' },
      status: { planned: 'مخطط', running: 'جارٍ التراجع…', done: 'تم', failed: 'انتهى مع إخفاقات' },
    },
    // AH2-T5 — إرجاع الوكيل إلى وقت سابق.
    rollback: {
      button: 'إرجاع الوكيل منذ…', title: 'إرجاع هذا الوكيل',
      lede: 'يوقف جلسات الوكيل الحية، ثم يتراجع عمّا فعلته كل جلساته منذ الوقت أدناه، الأحدث أولًا. السجل الذي غيّره شخص بعد ذلك يبقى كما هو.',
      since: 'منذ', sessions: '{count} جلسة منذ ذلك الوقت', confirm: 'أوقف وأرجِع',
    },
  },

};
