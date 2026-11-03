// F7-T2 — the portal shop pages (`/shop/:keyword`): products on sale to the
// member's account, quick order by SKU, the cart and checkout, and the
// account's orders with their tracking, over the portal's own shop routes
// (F7-T1). Its own entry point so only its route loads it.
export { StoreComponent, parseQuickOrder } from './store.component';
export type { QuickLine } from './store.component';
export { StoreService } from './store.service';
export type {
  Cart, CartLine, CatalogueItem, CheckedOut, GuestConfirm, GuestOrder, GuestStarted, OrderLine, ShippingOption, ShopOrder,
  StockBadge,
} from './store.service';
// F8-T10 — the store's page blocks (product grid, product detail, cart,
// checkout, order status), registered with the page runtime by the portal
// shell and loaded with this entry point only when a page shows one.
export {
  StoreCartComponent, StoreCheckoutComponent, StoreOrderStatusComponent, StoreProductDetailComponent, StoreProductGridComponent,
  checkoutMissing, productName, validCode,
} from './blocks/store-blocks';
export { StoreBasket, basketTotal, cents, fromCents, shownPrice } from './blocks/store-basket';
export type { BasketLine } from './blocks/store-basket';
