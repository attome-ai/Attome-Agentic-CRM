// F7-T2 — the portal shop pages (`/shop/:keyword`): products on sale to the
// member's account, quick order by SKU, the cart and checkout, and the
// account's orders with their tracking, over the portal's own shop routes
// (F7-T1). Its own entry point so only its route loads it.
export { StoreComponent, parseQuickOrder } from './store.component';
export type { QuickLine } from './store.component';
export { StoreService } from './store.service';
export type { Cart, CartLine, CatalogueItem, CheckedOut, OrderLine, ShopOrder } from './store.service';
