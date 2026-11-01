/**
 * A1-T14: the data-model diagram's own catalogue, registered on its route
 * (`provideLayerCatalog`). Its namespace, `dataModel`, is owned by this layer only.
 */
export const dataModelEn = {
  dataModel: {
    title: 'Data model',
    subtitle: 'Each entity with what it looks up, what it extends and what it is linked to. Check what uses a field before you change it.',
    entity: 'Entity',
    diagramLabel: 'Diagram of the selected entity and the entities around it',
    pick: 'Pick an entity to see it here.',
    storage: 'Storage',
    extends: 'extends',
    attribute: 'Attribute',
    type: 'Type',
    sensitivity: 'Sensitivity',
    usesEntity: 'What uses this entity',
    change_delete: 'Before delete',
    change_rename: 'Before rename',
    change_retype: 'Before type change',
    usesTitle: 'What uses {target}',
    usesNone: 'Nothing uses it.',
    breaking: 'Would break',
    affected: 'Uses it',
    hidden: '{n} more you may not see.',
    readOnly: 'Changes are made in a draft, which the designer does not offer yet; this view only reads.',
  },
};

export const dataModelAr = {
  dataModel: {
    title: 'نموذج البيانات',
    subtitle: 'كل كيان مع ما يبحث فيه وما يوسّعه وما يرتبط به. تحقق مما يستخدم الحقل قبل تغييره.',
    entity: 'الكيان',
    diagramLabel: 'مخطط للكيان المختار والكيانات المحيطة به',
    pick: 'اختر كيانًا لعرضه هنا.',
    storage: 'التخزين',
    extends: 'يوسّع',
    attribute: 'الحقل',
    type: 'النوع',
    sensitivity: 'الحساسية',
    usesEntity: 'ما الذي يستخدم هذا الكيان',
    change_delete: 'قبل الحذف',
    change_rename: 'قبل إعادة التسمية',
    change_retype: 'قبل تغيير النوع',
    usesTitle: 'ما الذي يستخدم {target}',
    usesNone: 'لا شيء يستخدمه.',
    breaking: 'سيتعطل',
    affected: 'يستخدمه',
    hidden: '{n} أخرى لا يمكنك رؤيتها.',
    readOnly: 'تُجرى التغييرات في مسودة، وهذا ما لا يقدمه المصمم بعد؛ هذا العرض للقراءة فقط.',
  },
};
