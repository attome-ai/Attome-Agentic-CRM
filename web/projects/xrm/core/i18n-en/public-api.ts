/*
 * @attome/xrm/core/i18n-en — xrm's English catalog, a lazy chunk the xrm
 * route tree loads before its first render (`provideXrmI18n()`). Kept out of
 * the route chunk so the catalog's growth never pushes that chunk past its
 * budget. Must never import `@attome/xrm/core/i18n`, which imports this entry
 * point dynamically.
 */
export { xrmEn } from './en.catalog';
